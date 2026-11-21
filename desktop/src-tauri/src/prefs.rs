//! The app's settings that are not secret (Windows Hello wanted, breach
//! checks, site icons), in `prefs.json` next to the vault.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase", default)]
pub struct Prefs {
    /// "Déverrouiller avec Windows Hello": re-enrolled after each password
    /// unlock while on.
    pub hello: bool,
    /// "Vérifier les fuites" (Watchtower): on by default, as on the Apple apps.
    pub check_breaches: bool,
    /// Site icons from the bundled icon pack.
    pub site_icons: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs {
            hello: false,
            check_breaches: true,
            site_icons: true,
        }
    }
}

pub fn path(dir: &Path) -> PathBuf {
    dir.join("prefs.json")
}

pub fn load(dir: &Path) -> Prefs {
    std::fs::read(path(dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save(dir: &Path, prefs: &Prefs) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(prefs).map_err(|_| "encode")?;
    let tmp = path(dir).with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| format!("write: {e}"))?;
    std::fs::rename(tmp, path(dir)).map_err(|e| format!("write: {e}"))
}
