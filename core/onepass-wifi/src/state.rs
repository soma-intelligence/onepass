//! What `onepass wifi` applied last, in the user's configuration
//! directory: `<config>/onepass/wifi-state.json`. SSIDs, system
//! references and fingerprints only, never a key.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Result, WifiError};

/// Current format of the file.
pub const VERSION: u32 = 1;

/// One network OnePass gave the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedEntry {
    pub os_ref: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    /// Networks OnePass added, by SSID.
    pub applied: BTreeMap<String, AppliedEntry>,
    /// System profiles `watch` already looked at (references), so a
    /// network the user removed from the vault is not imported again.
    #[serde(default)]
    pub seen: BTreeSet<String>,
    /// Profiles that appeared while `watch` could not unlock the vault:
    /// imported at the next unlock (the key stays in the system).
    #[serde(default)]
    pub pending: BTreeSet<String>,
}

impl Default for State {
    fn default() -> State {
        State {
            version: VERSION,
            applied: BTreeMap::new(),
            seen: BTreeSet::new(),
            pending: BTreeSet::new(),
        }
    }
}

/// The user's configuration directory: `%APPDATA%` on Windows,
/// `$XDG_CONFIG_HOME` or `~/.config` elsewhere.
pub fn config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("APPDATA").map(PathBuf::from);
    }
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")),
    }
}

/// `<config>/onepass/wifi-state.json`.
pub fn default_path() -> Result<PathBuf> {
    config_dir()
        .map(|d| d.join("onepass").join("wifi-state.json"))
        .ok_or_else(|| WifiError::new("no configuration directory (HOME or APPDATA unset)"))
}

impl State {
    /// The state at `path`; a missing file is an empty state.
    pub fn load(path: &Path) -> Result<State> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
            Err(_) => return Err(WifiError::new("cannot read the Wi-Fi state file")),
        };
        let state: State = serde_json::from_slice(&bytes)
            .map_err(|_| WifiError::new("the Wi-Fi state file is damaged"))?;
        if state.version != VERSION {
            return Err(WifiError::new("unknown Wi-Fi state file version"));
        }
        Ok(state)
    }

    /// Write atomically (temporary file, then rename), private to the
    /// user on Unix.
    pub fn save(&self, path: &Path) -> Result<()> {
        let fail = || WifiError::new("cannot write the Wi-Fi state file");
        let dir = path.parent().ok_or_else(fail)?;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).map_err(|_| fail())?;
        let json = serde_json::to_vec_pretty(self).map_err(|_| fail())?;
        let tmp = path.with_extension("json.tmp");
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|_| fail())?;
        f.write_all(&json).map_err(|_| fail())?;
        f.sync_all().map_err(|_| fail())?;
        fs::rename(&tmp, path).map_err(|_| fail())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("wifi-state.json");
        assert_eq!(State::load(&path).unwrap(), State::default());
        let mut s = State::default();
        s.applied.insert(
            "Home".into(),
            AppliedEntry {
                os_ref: "uuid-1".into(),
                fingerprint: "ab".into(),
            },
        );
        s.seen.insert("uuid-9".into());
        s.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), s);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::write(&path, b"{not json").unwrap();
        assert!(State::load(&path).is_err());
    }
}
