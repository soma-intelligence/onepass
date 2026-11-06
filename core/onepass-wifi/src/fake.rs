//! A [`Backend`] kept in a JSON file, standing in for a system in tests
//! (`ONEPASS_DEV_WIFI_FAKE=<file>` in debug builds of the CLI). It holds
//! keys in clear: development data only.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Auth, Backend, OsNetwork, Profile, Read, Result, WifiError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FakeProfile {
    pub os_ref: String,
    pub ssid: String,
    pub psk: String,
    /// `wpa2`, `wpa3`, `open`, `enterprise`, or `locked` (key refused).
    pub auth: String,
    pub hidden: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    next: u64,
    profiles: Vec<FakeProfile>,
}

pub struct FileBackend(pub PathBuf);

impl FileBackend {
    fn load(&self) -> Result<Store> {
        match fs::read(&self.0) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| WifiError::new("fake: bad file")),
            Err(_) => Ok(Store::default()),
        }
    }

    fn save(&self, s: &Store) -> Result<()> {
        let b = serde_json::to_vec_pretty(s).map_err(|_| WifiError::new("fake: encode"))?;
        fs::write(&self.0, b).map_err(|_| WifiError::new("fake: write"))
    }

    fn profile(net: &OsNetwork, os_ref: String) -> FakeProfile {
        FakeProfile {
            os_ref,
            ssid: net.ssid.clone(),
            psk: net.psk.to_string(),
            auth: match net.auth {
                Auth::Wpa2Psk => "wpa2",
                Auth::Wpa3Sae => "wpa3",
            }
            .to_owned(),
            hidden: net.hidden,
        }
    }
}

impl Backend for FileBackend {
    fn list(&mut self) -> Result<Vec<Profile>> {
        Ok(self
            .load()?
            .profiles
            .into_iter()
            .map(|p| Profile {
                os_ref: p.os_ref,
                ssid: p.ssid,
            })
            .collect())
    }

    fn read(&mut self, profile: &Profile) -> Result<Read> {
        let s = self.load()?;
        let Some(p) = s.profiles.iter().find(|p| p.os_ref == profile.os_ref) else {
            return Err(WifiError::new("fake: no such profile"));
        };
        let auth = match p.auth.as_str() {
            "wpa2" => Auth::Wpa2Psk,
            "wpa3" => Auth::Wpa3Sae,
            "locked" => return Ok(Read::Unavailable),
            _ => return Ok(Read::NotPersonal),
        };
        Ok(Read::Personal(OsNetwork {
            ssid: p.ssid.clone(),
            psk: Zeroizing::new(p.psk.clone()),
            auth,
            hidden: p.hidden,
        }))
    }

    fn add(&mut self, net: &OsNetwork) -> Result<String> {
        let mut s = self.load()?;
        s.next += 1;
        let os_ref = format!("fake-{}", s.next);
        s.profiles.push(Self::profile(net, os_ref.clone()));
        self.save(&s)?;
        Ok(os_ref)
    }

    fn update(&mut self, os_ref: &str, net: &OsNetwork) -> Result<String> {
        let mut s = self.load()?;
        let p = s
            .profiles
            .iter_mut()
            .find(|p| p.os_ref == os_ref)
            .ok_or_else(|| WifiError::new("fake: no such profile"))?;
        *p = Self::profile(net, os_ref.to_owned());
        self.save(&s)?;
        Ok(os_ref.to_owned())
    }

    fn remove(&mut self, os_ref: &str) -> Result<()> {
        let mut s = self.load()?;
        let before = s.profiles.len();
        s.profiles.retain(|p| p.os_ref != os_ref);
        if s.profiles.len() == before {
            return Err(WifiError::new("fake: no such profile"));
        }
        self.save(&s)
    }
}
