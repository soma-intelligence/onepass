//! Linux: NetworkManager over the system D-Bus.
//!
//! - Add: `Settings.AddConnection` with a `802-11-wireless-security`
//!   setting (`wpa-psk` or `sae`). The connection is restricted to the
//!   current user (`connection.permissions = ["user:<name>"]`), so
//!   NetworkManager's polkit rule `settings.modify.own` applies, which a
//!   local active session has without a prompt on the common
//!   distributions. The key stays with NetworkManager (`psk-flags` 0,
//!   kept in its root-only keyfile), the NetworkManager default.
//! - Read: `Connection.GetSettings`, then `GetSecrets` for the key: polkit
//!   may ask once for networks that are not the user's own.
//! - List: `Settings.ListConnections`, Wi-Fi connections only.
//!
//! Everything goes over D-Bus: no secret on a command line. The settings
//! maps are built and read in a neutral form ([`Settings`]) so they are
//! tested on every platform; only the D-Bus calls are Linux only.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::{Auth, OsNetwork, Read};

/// A value of a NetworkManager setting, the subset OnePass writes and
/// reads.
#[derive(Clone, PartialEq, Eq)]
pub enum Val {
    Str(String),
    Bytes(Vec<u8>),
    Bool(bool),
    U32(u32),
    StrList(Vec<String>),
    /// A secret string (the PSK): same wire type as `Str`.
    Secret(Zeroizing<String>),
}

impl std::fmt::Debug for Val {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Val::Str(s) => write!(f, "Str({s:?})"),
            Val::Bytes(b) => write!(f, "Bytes({b:?})"),
            Val::Bool(b) => write!(f, "Bool({b})"),
            Val::U32(n) => write!(f, "U32({n})"),
            Val::StrList(l) => write!(f, "StrList({l:?})"),
            Val::Secret(_) => f.write_str("Secret([redacted])"),
        }
    }
}

/// `a{sa{sv}}` of NetworkManager, neutral.
pub type Settings = BTreeMap<String, BTreeMap<String, Val>>;

pub const WIRELESS: &str = "802-11-wireless";
pub const SECURITY: &str = "802-11-wireless-security";

/// The connection OnePass adds for `net`, for user `user`, with `uuid`.
pub fn connection_settings(net: &OsNetwork, user: &str, uuid: &str) -> Settings {
    let mut s = Settings::new();
    let mut put = |group: &str, key: &str, v: Val| {
        s.entry(group.to_owned())
            .or_default()
            .insert(key.to_owned(), v);
    };
    put("connection", "id", Val::Str(net.ssid.clone()));
    put("connection", "uuid", Val::Str(uuid.to_owned()));
    put("connection", "type", Val::Str(WIRELESS.to_owned()));
    put("connection", "autoconnect", Val::Bool(true));
    put(
        "connection",
        "permissions",
        Val::StrList(vec![format!("user:{user}")]),
    );
    put(WIRELESS, "ssid", Val::Bytes(net.ssid.as_bytes().to_vec()));
    put(WIRELESS, "mode", Val::Str("infrastructure".to_owned()));
    if net.hidden {
        put(WIRELESS, "hidden", Val::Bool(true));
    }
    let key_mgmt = match net.auth {
        Auth::Wpa2Psk => "wpa-psk",
        Auth::Wpa3Sae => "sae",
    };
    put(SECURITY, "key-mgmt", Val::Str(key_mgmt.to_owned()));
    put(SECURITY, "psk", Val::Secret(net.psk.clone()));
    put(SECURITY, "psk-flags", Val::U32(0));
    put("ipv4", "method", Val::Str("auto".to_owned()));
    put("ipv6", "method", Val::Str("auto".to_owned()));
    s
}

fn get<'a>(s: &'a Settings, group: &str, key: &str) -> Option<&'a Val> {
    s.get(group)?.get(key)
}

fn get_str<'a>(s: &'a Settings, group: &str, key: &str) -> Option<&'a str> {
    match get(s, group, key)? {
        Val::Str(v) => Some(v),
        Val::Secret(v) => Some(v.as_str()),
        _ => None,
    }
}

/// SSID of a Wi-Fi connection's settings (UTF-8 only), or `None` for
/// another kind of connection.
pub fn ssid_of(s: &Settings) -> Option<String> {
    if get_str(s, "connection", "type") != Some(WIRELESS) {
        return None;
    }
    match get(s, WIRELESS, "ssid")? {
        Val::Bytes(b) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

/// The network of a connection from its settings and its secrets (the
/// `GetSecrets` answer for [`SECURITY`]).
pub fn network_of(settings: &Settings, secrets: Option<&Settings>) -> Read {
    let Some(ssid) = ssid_of(settings) else {
        return Read::NotPersonal;
    };
    let auth = match get_str(settings, SECURITY, "key-mgmt") {
        Some("wpa-psk") => Auth::Wpa2Psk,
        Some("sae") => Auth::Wpa3Sae,
        // No security group (open), WEP (`none`), OWE, enterprise.
        _ => return Read::NotPersonal,
    };
    let hidden = matches!(get(settings, WIRELESS, "hidden"), Some(Val::Bool(true)));
    let psk = secrets
        .and_then(|s| get_str(s, SECURITY, "psk"))
        .or_else(|| get_str(settings, SECURITY, "psk"));
    match psk {
        Some(p) if !p.is_empty() => Read::Personal(OsNetwork {
            ssid,
            psk: Zeroizing::new(p.to_owned()),
            auth,
            hidden,
        }),
        _ => Read::Unavailable,
    }
}

/// A random version 4 UUID from 16 random bytes.
pub fn uuid_v4(mut b: [u8; 16]) -> String {
    if let Some(x) = b.get_mut(6) {
        *x = (*x & 0x0f) | 0x40;
    }
    if let Some(x) = b.get_mut(8) {
        *x = (*x & 0x3f) | 0x80;
    }
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        h.get(0..8).unwrap_or(""),
        h.get(8..12).unwrap_or(""),
        h.get(12..16).unwrap_or(""),
        h.get(16..20).unwrap_or(""),
        h.get(20..32).unwrap_or("")
    )
}

/// The systemd user unit that runs `exec_start` (already quoted) once the
/// graphical session is up, restarting it if it stops on an error.
pub fn systemd_unit(exec_start: &str) -> String {
    format!(
        "[Unit]\n\
         Description=OnePass Wi-Fi: networks of the vault on this computer\n\
         After=graphical-session.target NetworkManager.service\n\
         PartOf=graphical-session.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec_start}\n\
         Restart=on-failure\n\
         RestartSec=60\n\
         \n\
         [Install]\n\
         WantedBy=graphical-session.target\n"
    )
}

/// One `ExecStart` word: double quoted, with `\`, `"` and the specifier
/// `%` escaped as systemd wants.
pub fn systemd_quote(word: &str) -> String {
    let mut out = String::from("\"");
    for c in word.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(target_os = "linux")]
pub use nm::NetworkManager;

#[cfg(target_os = "linux")]
mod nm {
    use std::collections::HashMap;

    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

    use super::{SECURITY, Settings, Val, connection_settings, network_of, ssid_of, uuid_v4};
    use crate::{Backend, OsNetwork, Profile, Read, Result, WifiError};

    const DEST: &str = "org.freedesktop.NetworkManager";
    const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
    const SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
    const CONN_IFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";

    type Wire = HashMap<String, HashMap<String, OwnedValue>>;

    fn err(what: &str) -> impl Fn(zbus::Error) -> WifiError + '_ {
        move |_| WifiError::new(format!("NetworkManager: {what} failed"))
    }

    fn to_wire(s: &Settings) -> Result<Wire> {
        let mut out = Wire::new();
        for (group, kv) in s {
            let mut g = HashMap::new();
            for (k, v) in kv {
                let value = match v {
                    Val::Str(s) => Value::from(s.as_str()),
                    Val::Secret(s) => Value::from(s.as_str()),
                    Val::Bytes(b) => Value::from(b.clone()),
                    Val::Bool(b) => Value::from(*b),
                    Val::U32(n) => Value::from(*n),
                    Val::StrList(l) => Value::from(l.clone()),
                };
                let owned = OwnedValue::try_from(value)
                    .map_err(|_| WifiError::new("NetworkManager: bad setting"))?;
                g.insert(k.clone(), owned);
            }
            out.insert(group.clone(), g);
        }
        Ok(out)
    }

    /// The keys OnePass reads, in neutral form; others are left out.
    fn from_wire(w: Wire) -> Settings {
        let mut out = Settings::new();
        for (group, kv) in w {
            let mut g = std::collections::BTreeMap::new();
            for (k, v) in kv {
                let val = match k.as_str() {
                    "ssid" => Vec::<u8>::try_from(v).ok().map(Val::Bytes),
                    "hidden" => bool::try_from(&v).ok().map(Val::Bool),
                    "psk" => String::try_from(v)
                        .ok()
                        .map(|s| Val::Secret(zeroize::Zeroizing::new(s))),
                    "id" | "uuid" | "type" | "key-mgmt" => String::try_from(v).ok().map(Val::Str),
                    _ => None,
                };
                if let Some(val) = val {
                    g.insert(k, val);
                }
            }
            out.insert(group, g);
        }
        out
    }

    /// NetworkManager as a [`Backend`], on the system bus.
    pub struct NetworkManager {
        bus: Connection,
        user: String,
    }

    impl NetworkManager {
        /// Connect to the system bus. `user` is the login name the added
        /// connections are restricted to.
        pub fn connect(user: &str) -> Result<NetworkManager> {
            let bus = Connection::system()
                .map_err(|_| WifiError::new("cannot reach the system D-Bus"))?;
            Ok(NetworkManager {
                bus,
                user: user.to_owned(),
            })
        }

        fn settings(&self) -> Result<Proxy<'_>> {
            Proxy::new(&self.bus, DEST, SETTINGS_PATH, SETTINGS_IFACE).map_err(err("Settings"))
        }

        fn conn(&self, path: &str) -> Result<Proxy<'_>> {
            Proxy::new(&self.bus, DEST, path.to_owned(), CONN_IFACE).map_err(err("Connection"))
        }

        fn path_of(&self, uuid: &str) -> Result<OwnedObjectPath> {
            self.settings()?
                .call("GetConnectionByUuid", &(uuid,))
                .map_err(err("GetConnectionByUuid"))
        }

        fn random_uuid() -> Result<String> {
            use std::io::Read as _;
            let mut b = [0u8; 16];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut b))
                .map_err(|_| WifiError::new("no randomness"))?;
            Ok(uuid_v4(b))
        }
    }

    impl Backend for NetworkManager {
        fn list(&mut self) -> Result<Vec<Profile>> {
            let paths: Vec<OwnedObjectPath> = self
                .settings()?
                .call("ListConnections", &())
                .map_err(err("ListConnections"))?;
            let mut out = Vec::new();
            for p in paths {
                let Ok(w) = self
                    .conn(p.as_str())?
                    .call::<_, _, Wire>("GetSettings", &())
                else {
                    continue;
                };
                let s = from_wire(w);
                let (Some(ssid), Some(Val::Str(uuid))) =
                    (ssid_of(&s), s.get("connection").and_then(|c| c.get("uuid")))
                else {
                    continue;
                };
                out.push(Profile {
                    os_ref: uuid.clone(),
                    ssid,
                });
            }
            Ok(out)
        }

        fn read(&mut self, profile: &Profile) -> Result<Read> {
            let path = self.path_of(&profile.os_ref)?;
            let conn = self.conn(path.as_str())?;
            let settings = from_wire(conn.call("GetSettings", &()).map_err(err("GetSettings"))?);
            // Refused (polkit dismissed) or none stored: unavailable.
            let secrets = conn
                .call::<_, _, Wire>("GetSecrets", &(SECURITY,))
                .ok()
                .map(from_wire);
            Ok(network_of(&settings, secrets.as_ref()))
        }

        fn add(&mut self, net: &OsNetwork) -> Result<String> {
            let uuid = Self::random_uuid()?;
            let wire = to_wire(&connection_settings(net, &self.user, &uuid))?;
            let _: OwnedObjectPath = self
                .settings()?
                .call("AddConnection", &(wire,))
                .map_err(err("AddConnection"))?;
            Ok(uuid)
        }

        fn update(&mut self, os_ref: &str, net: &OsNetwork) -> Result<String> {
            let path = self.path_of(os_ref)?;
            let wire = to_wire(&connection_settings(net, &self.user, os_ref))?;
            self.conn(path.as_str())?
                .call::<_, _, ()>("Update", &(wire,))
                .map_err(err("Update"))?;
            Ok(os_ref.to_owned())
        }

        fn remove(&mut self, os_ref: &str) -> Result<()> {
            let path = self.path_of(os_ref)?;
            self.conn(path.as_str())?
                .call::<_, _, ()>("Delete", &())
                .map_err(err("Delete"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(ssid: &str, auth: Auth, hidden: bool) -> OsNetwork {
        OsNetwork {
            ssid: ssid.into(),
            psk: Zeroizing::new("p\"ss & word".into()),
            auth,
            hidden,
        }
    }

    #[test]
    fn settings_of_a_wpa2_network() {
        let s = connection_settings(&net("Tom & \"Jerry\"", Auth::Wpa2Psk, false), "ana", "u-1");
        assert_eq!(
            get(&s, "connection", "permissions"),
            Some(&Val::StrList(vec!["user:ana".into()]))
        );
        assert_eq!(get_str(&s, "connection", "type"), Some(WIRELESS));
        assert_eq!(get_str(&s, "connection", "uuid"), Some("u-1"));
        assert_eq!(
            get(&s, WIRELESS, "ssid"),
            Some(&Val::Bytes(b"Tom & \"Jerry\"".to_vec()))
        );
        assert_eq!(get_str(&s, SECURITY, "key-mgmt"), Some("wpa-psk"));
        assert_eq!(get_str(&s, SECURITY, "psk"), Some("p\"ss & word"));
        assert_eq!(get(&s, SECURITY, "psk-flags"), Some(&Val::U32(0)));
        assert_eq!(get(&s, WIRELESS, "hidden"), None);
        assert!(!format!("{s:?}").contains("word"));
    }

    #[test]
    fn settings_of_a_hidden_wpa3_unicode_network() {
        let n = net("Café ☕", Auth::Wpa3Sae, true);
        let s = connection_settings(&n, "ana", "u-2");
        assert_eq!(get_str(&s, SECURITY, "key-mgmt"), Some("sae"));
        assert_eq!(get(&s, WIRELESS, "hidden"), Some(&Val::Bool(true)));
        assert_eq!(
            get(&s, WIRELESS, "ssid"),
            Some(&Val::Bytes("Café ☕".as_bytes().to_vec()))
        );
        // Round trip: what we write reads back as the same network.
        assert_eq!(network_of(&s, None), Read::Personal(n));
    }

    #[test]
    fn reading_settings_and_secrets() {
        let n = net("Home", Auth::Wpa2Psk, false);
        let mut s = connection_settings(&n, "ana", "u");
        let secrets = s.clone();
        s.get_mut(SECURITY).unwrap().remove("psk");
        assert_eq!(network_of(&s, Some(&secrets)), Read::Personal(n));
        assert_eq!(network_of(&s, None), Read::Unavailable);
        let mut ent = s.clone();
        ent.get_mut(SECURITY)
            .unwrap()
            .insert("key-mgmt".into(), Val::Str("wpa-eap".into()));
        assert_eq!(network_of(&ent, Some(&secrets)), Read::NotPersonal);
        let mut open = s.clone();
        open.remove(SECURITY);
        assert_eq!(network_of(&open, None), Read::NotPersonal);
        let mut wired = s.clone();
        wired
            .get_mut("connection")
            .unwrap()
            .insert("type".into(), Val::Str("802-3-ethernet".into()));
        assert_eq!(ssid_of(&wired), None);
        let mut latin1 = s;
        latin1
            .get_mut(WIRELESS)
            .unwrap()
            .insert("ssid".into(), Val::Bytes(vec![0x43, 0xe9]));
        assert_eq!(ssid_of(&latin1), None);
    }

    #[test]
    fn uuid_and_unit() {
        let u = uuid_v4([0xff; 16]);
        assert_eq!(u, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(
            systemd_quote("/home/a b/%h/\"x\"/$y"),
            "\"/home/a b/%%h/\\\"x\\\"/$$y\""
        );
        let unit = systemd_unit("\"/usr/bin/onepass\" \"wifi\" \"watch\"");
        assert!(unit.contains("ExecStart=\"/usr/bin/onepass\" \"wifi\" \"watch\"\n"));
        assert!(unit.contains("WantedBy=graphical-session.target"));
    }
}
