//! Windows: per-user WLAN profiles through `netsh wlan`.
//!
//! - Add: the profile XML (SSID in hex and escaped text, WPA2PSK or
//!   WPA3SAE, joined automatically) goes to a file created only for this
//!   call in the user's `%TEMP%` (whose ACL already admits the user,
//!   SYSTEM and administrators only), then `netsh wlan add profile
//!   filename="..." user=current`; the file is overwritten and deleted
//!   right after, whatever the outcome. Per-user profiles need no
//!   administrator.
//! - Read: `netsh wlan show profile name="..." key=clear`, parsed with
//!   the English and French labels.
//! - List: `netsh wlan show profiles`, parsed by structure (any language).
//!
//! `netsh` writes in the OEM code page when piped: labels are matched on
//! their ASCII prefix, and a profile name outside ASCII may come back
//! altered (see [`Netsh::listing_is_exact`]).

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroizing;

use crate::exec::{Exec, SystemExec};
use crate::{Auth, Backend, OsNetwork, Profile, Read, Result, WifiError};

/// Escape `s` for XML text: `& < > " '`. Characters XML 1.0 forbids are
/// dropped (the SSID also goes in hex, which Windows prefers).
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => {}
            c => out.push(c),
        }
    }
    out
}

/// Upper-case hex of the SSID bytes, as the profile schema wants.
pub fn ssid_hex(ssid: &str) -> String {
    ssid.bytes().map(|b| format!("{b:02X}")).collect()
}

/// Name of the profile OnePass gives a network: the SSID, with the double
/// quote (which `netsh` cannot take inside `name="..."`) and control
/// characters replaced by `_`.
pub fn profile_name(ssid: &str) -> String {
    ssid.chars()
        .map(|c| if c == '"' || c.is_control() { '_' } else { c })
        .collect()
}

/// The WLAN profile XML of `net`, named `name`. Holds the key in clear:
/// the caller keeps it off disk except for the short-lived add file.
pub fn profile_xml(name: &str, net: &OsNetwork) -> Zeroizing<String> {
    let (auth, encryption) = match net.auth {
        Auth::Wpa2Psk => ("WPA2PSK", "AES"),
        Auth::Wpa3Sae => ("WPA3SAE", "AES"),
    };
    // 64 hex digits are a raw key, anything else a passphrase.
    let key_type = if net.psk.len() == 64 && net.psk.bytes().all(|b| b.is_ascii_hexdigit()) {
        "networkKey"
    } else {
        "passPhrase"
    };
    let mut x = Zeroizing::new(String::with_capacity(1024));
    x.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    x.push_str("<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n");
    x.push_str(&format!("  <name>{}</name>\n", xml_escape(name)));
    x.push_str("  <SSIDConfig>\n    <SSID>\n");
    x.push_str(&format!("      <hex>{}</hex>\n", ssid_hex(&net.ssid)));
    x.push_str(&format!("      <name>{}</name>\n", xml_escape(&net.ssid)));
    x.push_str("    </SSID>\n");
    x.push_str(&format!(
        "    <nonBroadcast>{}</nonBroadcast>\n",
        if net.hidden { "true" } else { "false" }
    ));
    x.push_str("  </SSIDConfig>\n");
    x.push_str("  <connectionType>ESS</connectionType>\n");
    x.push_str("  <connectionMode>auto</connectionMode>\n");
    x.push_str("  <MSM>\n    <security>\n      <authEncryption>\n");
    x.push_str(&format!(
        "        <authentication>{auth}</authentication>\n"
    ));
    x.push_str(&format!("        <encryption>{encryption}</encryption>\n"));
    x.push_str("        <useOneX>false</useOneX>\n");
    x.push_str("      </authEncryption>\n      <sharedKey>\n");
    x.push_str(&format!("        <keyType>{key_type}</keyType>\n"));
    x.push_str("        <protected>false</protected>\n");
    x.push_str("        <keyMaterial>");
    x.push_str(&xml_escape(&net.psk));
    x.push_str("</keyMaterial>\n");
    x.push_str("      </sharedKey>\n    </security>\n  </MSM>\n</WLANProfile>\n");
    x
}

/// Lines of a `netsh` output, without carriage returns.
fn lines(out: &str) -> impl Iterator<Item = &str> {
    out.split('\n').map(|l| l.trim_end_matches('\r'))
}

/// Profile names of `netsh wlan show profiles`, in any language: every
/// indented `label : name` line after a dashed rule. Names keep their
/// spaces; duplicates (one per interface) are dropped.
pub fn parse_profile_names(out: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut in_section = false;
    for line in lines(out) {
        let t = line.trim();
        if !t.is_empty() && t.chars().all(|c| c == '-') {
            in_section = true;
            continue;
        }
        if !in_section || !line.starts_with(' ') {
            if !line.starts_with(' ') && !t.is_empty() {
                in_section = false;
            }
            continue;
        }
        let Some((_, name)) = line.split_once(" : ") else {
            continue;
        };
        if name.is_empty() || name.starts_with('<') && name.ends_with('>') {
            continue;
        }
        if !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    }
    names
}

/// The value of `line` if it is `<label><up to 2 chars> : <value>` for one
/// of `labels` (a label may stop before an accented letter, which the OEM
/// code page turns into something else).
fn value_of<'a>(line: &'a str, labels: &[&str]) -> Option<&'a str> {
    let t = line.trim_start();
    for label in labels {
        let Some(rest) = t.strip_prefix(label) else {
            continue;
        };
        let Some((between, value)) = rest.split_once(':') else {
            continue;
        };
        if between.trim().chars().count() > 2 {
            continue;
        }
        return Some(value.strip_prefix(' ').unwrap_or(value));
    }
    None
}

const SSID_LABELS: &[&str] = &["SSID name", "Nom du SSID"];
const AUTH_LABELS: &[&str] = &["Authentication", "Authentification"];
const KEY_LABELS: &[&str] = &["Key Content", "Contenu de la cl"];
const BROADCAST_LABELS: &[&str] = &["Network broadcast", "Diffusion r"];

/// What `netsh wlan show profile name=... key=clear` says of a profile.
pub fn parse_profile(out: &str) -> Read {
    let mut ssid: Option<String> = None;
    let mut auths: Vec<String> = Vec::new();
    let mut key: Option<Zeroizing<String>> = None;
    let mut hidden = false;
    for line in lines(out) {
        if let Some(v) = value_of(line, SSID_LABELS) {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(v);
            ssid.get_or_insert_with(|| v.to_owned());
        } else if let Some(v) = value_of(line, AUTH_LABELS) {
            auths.push(v.trim().to_lowercase().replace([' ', '-'], ""));
        } else if let Some(v) = value_of(line, KEY_LABELS) {
            key = Some(Zeroizing::new(v.to_owned()));
        } else if let Some(v) = value_of(line, BROADCAST_LABELS) {
            let v = v.to_lowercase();
            hidden = v.contains("not broadcasting") || v.contains("ne diffuse pas");
        }
    }
    let has = |words: &[&str]| auths.iter().any(|a| words.iter().any(|w| a.contains(w)));
    if auths.is_empty() || has(&["enterprise", "entreprise", "802.1x"]) {
        return Read::NotPersonal;
    }
    let auth = if has(&[
        "wpa2personal",
        "wpa2personnel",
        "wpapersonal",
        "wpapersonnel",
    ]) {
        Auth::Wpa2Psk
    } else if has(&["wpa3personal", "wpa3personnel", "wpa3sae"]) {
        Auth::Wpa3Sae
    } else {
        // Open, WEP, or something unknown.
        return Read::NotPersonal;
    };
    match (ssid, key) {
        (Some(ssid), Some(psk)) if !ssid.is_empty() && !psk.is_empty() => {
            Read::Personal(OsNetwork {
                ssid,
                psk,
                auth,
                hidden,
            })
        }
        _ => Read::Unavailable,
    }
}

/// `"s"` for a `netsh` argument, or `None` if `s` holds a double quote.
fn quoted(s: &str) -> Option<String> {
    (!s.contains('"')).then(|| format!("\"{s}\""))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A file only this call uses, in `dir`, holding `content`, removed (after
/// an overwrite with zeros) when dropped.
struct TempFile(PathBuf);

impl TempFile {
    fn create(dir: &Path, content: &[u8]) -> Result<TempFile> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(
            "onepass-wifi-{}-{nanos:x}-{n}.xml",
            std::process::id()
        ));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let fail = || WifiError::new("cannot write the temporary profile file");
        let mut f = opts.open(&path).map_err(|_| fail())?;
        let file = TempFile(path);
        f.write_all(content).map_err(|_| fail())?;
        f.sync_all().map_err(|_| fail())?;
        Ok(file)
    }
}

/// Profile files older than this are left over by a run that died before
/// its cleanup (power cut, killed process): never one in use.
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(120);

/// Overwrite and delete the profile files of earlier runs that died before
/// their cleanup, so a key never stays in `dir` past the next add.
pub fn sweep_stale(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with("onepass-wifi-") && name.ends_with(".xml")) {
            continue;
        }
        let Ok(meta) = e.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let old = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= STALE_AFTER);
        if old {
            drop(TempFile(e.path()));
        }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Ok(meta) = fs::metadata(&self.0)
            && let Ok(mut f) = fs::OpenOptions::new().write(true).open(&self.0)
        {
            let zeros = vec![0u8; usize::try_from(meta.len()).unwrap_or(0)];
            let _ = f.write_all(&zeros);
            let _ = f.sync_all();
        }
        let _ = fs::remove_file(&self.0);
    }
}

/// `netsh wlan` as a [`Backend`].
pub struct Netsh<E: Exec> {
    pub exec: E,
    pub program: PathBuf,
    pub temp_dir: PathBuf,
}

impl Netsh<SystemExec> {
    /// The system's `netsh.exe` (under `%SystemRoot%`, never from `PATH`)
    /// and the user's temporary directory.
    pub fn system() -> Netsh<SystemExec> {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        Netsh {
            exec: SystemExec,
            program: PathBuf::from(root).join("System32").join("netsh.exe"),
            temp_dir: std::env::temp_dir(),
        }
    }
}

impl<E: Exec> Netsh<E> {
    fn netsh(&mut self, args: &[String]) -> Result<crate::exec::Output> {
        self.exec.run(&self.program, args)
    }

    /// Whether the listing can be trusted to show `os_ref` exactly: not
    /// for names outside ASCII, which the OEM code page may alter.
    pub fn listing_is_exact(os_ref: &str) -> bool {
        os_ref.is_ascii()
    }
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

impl<E: Exec> Backend for Netsh<E> {
    fn list(&mut self) -> Result<Vec<Profile>> {
        let out = self.netsh(&args(&["wlan", "show", "profiles"]))?;
        if !out.ok {
            // No WLAN service or no Wi-Fi adapter: nothing saved here.
            return Ok(Vec::new());
        }
        Ok(parse_profile_names(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .map(|name| Profile {
                os_ref: name.clone(),
                ssid: name,
            })
            .collect())
    }

    fn read(&mut self, profile: &Profile) -> Result<Read> {
        let Some(name) = quoted(&profile.os_ref) else {
            return Ok(Read::Unavailable);
        };
        let mut a = args(&["wlan", "show", "profile"]);
        a.push(format!("name={name}"));
        a.push("key=clear".to_owned());
        let out = self.netsh(&a)?;
        let stdout = Zeroizing::new(out.stdout);
        if !out.ok {
            return Ok(Read::Unavailable);
        }
        let text = Zeroizing::new(String::from_utf8_lossy(&stdout).into_owned());
        Ok(parse_profile(&text))
    }

    fn add(&mut self, net: &OsNetwork) -> Result<String> {
        let name = profile_name(&net.ssid);
        let xml = profile_xml(&name, net);
        sweep_stale(&self.temp_dir);
        let file = TempFile::create(&self.temp_dir, xml.as_bytes())?;
        let path = file.0.to_string_lossy().into_owned();
        let path = quoted(&path).ok_or_else(|| WifiError::new("bad temporary path"))?;
        let mut a = args(&["wlan", "add", "profile"]);
        a.push(format!("filename={path}"));
        a.push("user=current".to_owned());
        let out = self.netsh(&a);
        drop(file);
        if !out?.ok {
            return Err(WifiError::new(format!(
                "netsh refused the profile of {}",
                net.ssid
            )));
        }
        Ok(name)
    }

    fn update(&mut self, os_ref: &str, net: &OsNetwork) -> Result<String> {
        // `add profile` on an existing name is refused on some versions:
        // delete first, a missing profile is fine.
        let _ = self.remove(os_ref);
        self.add(net)
    }

    fn remove(&mut self, os_ref: &str) -> Result<()> {
        let name = quoted(os_ref).ok_or_else(|| WifiError::new("bad profile name"))?;
        let mut a = args(&["wlan", "delete", "profile"]);
        a.push(format!("name={name}"));
        if !self.netsh(&a)?.ok {
            return Err(WifiError::new(format!("netsh could not delete {os_ref}")));
        }
        Ok(())
    }
}

/// Value of the `HKCU\...\Run` entry that starts the agent at logon.
pub const RUN_KEY: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
/// Name of that value.
pub const RUN_VALUE: &str = "OnePassWiFi";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::Output;

    fn net(ssid: &str, psk: &str, auth: Auth, hidden: bool) -> OsNetwork {
        OsNetwork {
            ssid: ssid.into(),
            psk: Zeroizing::new(psk.into()),
            auth,
            hidden,
        }
    }

    #[test]
    fn xml_escapes_ssid_and_key() {
        let n = net(
            "Tom & \"Jerry\" <5G>",
            "p&ss<word>'\"",
            Auth::Wpa2Psk,
            false,
        );
        let x = profile_xml(&profile_name(&n.ssid), &n);
        assert!(x.contains("<name>Tom &amp; _Jerry_ &lt;5G&gt;</name>"));
        assert!(x.contains("<name>Tom &amp; &quot;Jerry&quot; &lt;5G&gt;</name>"));
        assert!(x.contains("<keyMaterial>p&amp;ss&lt;word&gt;&apos;&quot;</keyMaterial>"));
        assert!(x.contains("<authentication>WPA2PSK</authentication>"));
        assert!(x.contains("<keyType>passPhrase</keyType>"));
        assert!(x.contains("<nonBroadcast>false</nonBroadcast>"));
        assert!(x.contains("<connectionMode>auto</connectionMode>"));
        // Nothing unescaped slipped into the document.
        assert_eq!(x.matches('<').count(), x.matches('>').count());
    }

    #[test]
    fn xml_unicode_ssid_has_exact_hex() {
        let n = net("Café ☕", "12345678", Auth::Wpa3Sae, true);
        let x = profile_xml("Café ☕", &n);
        assert!(x.contains("<hex>436166C3A920E29895</hex>"));
        assert!(x.contains("<name>Café ☕</name>"));
        assert!(x.contains("<authentication>WPA3SAE</authentication>"));
        assert!(x.contains("<nonBroadcast>true</nonBroadcast>"));
        let raw = net("x", &"ab".repeat(32), Auth::Wpa2Psk, false);
        assert!(profile_xml("x", &raw).contains("<keyType>networkKey</keyType>"));
        // Control characters are dropped from text, kept in hex.
        assert_eq!(xml_escape("a\u{1}b"), "ab");
        assert_eq!(ssid_hex("a\u{1}"), "6101");
    }

    const PROFILES_EN: &str = "\r\nProfiles on interface Wi-Fi:\r\n\r\nGroup policy profiles (read only)\r\n---------------------------------\r\n    <None>\r\n\r\nUser profiles\r\n-------------\r\n    All User Profile     : HomeNet\r\n    Current User Profile : Cafe : Free Wi-Fi\r\n    All User Profile     : Tom & Jerry\r\n\r\nProfiles on interface Wi-Fi 2:\r\n\r\nUser profiles\r\n-------------\r\n    All User Profile     : HomeNet\r\n";

    const PROFILES_FR: &str = "\r\nProfils sur l'interface Wi-Fi\u{a0}:\r\n\r\nProfils de strat\u{fffd}gie de groupe (lecture seule)\r\n---------------------------------\r\n    <Aucun>\r\n\r\nProfils utilisateurs\r\n-------------------\r\n    Profil Tous les utilisateurs : Maison\r\n    Profil utilisateur actuel : Bureau 5G\r\n";

    #[test]
    fn profile_names_in_english_and_french() {
        assert_eq!(
            parse_profile_names(PROFILES_EN),
            ["HomeNet", "Cafe : Free Wi-Fi", "Tom & Jerry"]
        );
        assert_eq!(parse_profile_names(PROFILES_FR), ["Maison", "Bureau 5G"]);
        assert!(parse_profile_names("There is no wireless interface on the system.").is_empty());
    }

    const DETAIL_EN: &str = "\r\nProfile HomeNet on interface Wi-Fi:\r\n=======================================================================\r\n\r\nApplied: All User Profile\r\n\r\nProfile information\r\n-------------------\r\n    Version                : 1\r\n    Type                   : Wireless LAN\r\n    Name                   : HomeNet\r\n    Control options        :\r\n        Connection mode    : Connect automatically\r\n        Network broadcast  : Connect even if this network is not broadcasting\r\n        AutoSwitch         : Do not switch to other networks\r\n\r\nConnectivity settings\r\n---------------------\r\n    Number of SSIDs        : 1\r\n    SSID name              : \"HomeNet\"\r\n    Network type           : Infrastructure\r\n\r\nSecurity settings\r\n-----------------\r\n    Authentication         : WPA2-Personal\r\n    Cipher                 : CCMP\r\n    Authentication         : WPA2-Personal\r\n    Cipher                 : GCMP\r\n    Security key           : Present\r\n    Key Content            : correct : horse \r\n";

    const DETAIL_FR: &str = "\r\nProfil Maison sur l'interface Wi-Fi\u{a0}:\r\n=======================================================================\r\n\r\nAppliqu\u{fffd} : Profil Tous les utilisateurs\r\n\r\nInformations sur le profil\r\n-------------------\r\n    Version                : 1\r\n    Nom                    : Maison\r\n    Options de contr\u{fffd}le    :\r\n        Mode de connexion  : Connexion automatique\r\n        Diffusion r\u{fffd}seau   : Se connecter uniquement si ce r\u{fffd}seau diffuse\r\n\r\nParam\u{fffd}tres de connectivit\u{fffd}\r\n---------------------\r\n    Nombre de SSID         : 1\r\n    Nom du SSID            : \"Maison\"\r\n    Type de r\u{fffd}seau        : Infrastructure\r\n\r\nParam\u{fffd}tres de s\u{fffd}curit\u{fffd}\r\n-----------------\r\n    Authentification         : WPA3 - Personnel\r\n    Chiffrement              : CCMP\r\n    Cl\u{fffd} de s\u{fffd}curit\u{fffd}          : Pr\u{fffd}sent\r\n    Contenu de la cl\u{fffd}        : mot-de-passe-fr\r\n";

    #[test]
    fn profile_detail_in_english() {
        let Read::Personal(n) = parse_profile(DETAIL_EN) else {
            panic!("not personal");
        };
        assert_eq!(n.ssid, "HomeNet");
        assert_eq!(n.psk.as_str(), "correct : horse ");
        assert_eq!(n.auth, Auth::Wpa2Psk);
        assert!(n.hidden);
    }

    #[test]
    fn profile_detail_in_french() {
        let Read::Personal(n) = parse_profile(DETAIL_FR) else {
            panic!("not personal");
        };
        assert_eq!(n.ssid, "Maison");
        assert_eq!(n.psk.as_str(), "mot-de-passe-fr");
        assert_eq!(n.auth, Auth::Wpa3Sae);
        assert!(!n.hidden);
    }

    #[test]
    fn profile_detail_refusals() {
        let enterprise = DETAIL_EN.replace("WPA2-Personal", "WPA2-Enterprise");
        assert_eq!(parse_profile(&enterprise), Read::NotPersonal);
        let open = DETAIL_EN.replace("WPA2-Personal", "Open");
        assert_eq!(parse_profile(&open), Read::NotPersonal);
        let fr_ent = DETAIL_FR.replace("WPA3 - Personnel", "WPA2 - Entreprise");
        assert_eq!(parse_profile(&fr_ent), Read::NotPersonal);
        // Key not shown (no rights): unavailable, not a guess.
        let no_key = DETAIL_EN.replace("    Key Content            : correct : horse \r\n", "");
        assert_eq!(parse_profile(&no_key), Read::Unavailable);
    }

    /// Records each call; answers from a script. Captures the add file.
    #[derive(Default)]
    struct Fake {
        calls: Vec<Vec<String>>,
        files: Vec<String>,
        answers: Vec<(bool, String)>,
    }

    impl Exec for Fake {
        fn run(&mut self, _: &Path, args: &[String]) -> Result<Output> {
            if let Some(f) = args.iter().find_map(|a| a.strip_prefix("filename=")) {
                let path = f.trim_matches('"');
                self.files.push(fs::read_to_string(path).unwrap());
            }
            self.calls.push(args.to_vec());
            let (ok, out) = if self.answers.is_empty() {
                (true, String::new())
            } else {
                self.answers.remove(0)
            };
            Ok(Output {
                ok,
                stdout: out.into_bytes(),
            })
        }
    }

    #[test]
    fn netsh_add_writes_then_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Netsh {
            exec: Fake::default(),
            program: "netsh.exe".into(),
            temp_dir: dir.path().into(),
        };
        let n = net("Home \"5G\"", "secret-key-1", Auth::Wpa2Psk, false);
        let name = b.add(&n).unwrap();
        assert_eq!(name, "Home _5G_");
        let call = &b.exec.calls[0];
        assert_eq!(&call[..3], ["wlan", "add", "profile"]);
        assert_eq!(call[4], "user=current");
        // The key went through the file only, never an argument.
        assert!(b.exec.files[0].contains("secret-key-1"));
        assert!(!call.iter().any(|a| a.contains("secret-key-1")));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        // A refusal still deletes the file and names no secret.
        b.exec.answers.push((false, String::new()));
        let e = b.add(&n).unwrap_err();
        assert!(!e.0.contains("secret-key-1"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn stale_profile_files_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("onepass-wifi-1-ab-0.xml");
        let fresh = dir.path().join("onepass-wifi-2-cd-0.xml");
        let other = dir.path().join("notes.xml");
        for p in [&stale, &fresh, &other] {
            fs::write(p, b"<keyMaterial>left-over</keyMaterial>").unwrap();
        }
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
        fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        sweep_stale(dir.path());
        assert!(!stale.exists());
        // A file of a run still going, and files that are not ours, stay.
        assert!(fresh.exists());
        assert!(other.exists());
    }

    #[test]
    fn netsh_list_read_remove() {
        let mut b = Netsh {
            exec: Fake::default(),
            program: "netsh.exe".into(),
            temp_dir: std::env::temp_dir(),
        };
        b.exec.answers.push((true, PROFILES_EN.into()));
        b.exec.answers.push((true, DETAIL_EN.into()));
        let list = b.list().unwrap();
        assert_eq!(list.len(), 3);
        assert!(matches!(b.read(&list[0]).unwrap(), Read::Personal(_)));
        assert_eq!(
            b.exec.calls[1],
            ["wlan", "show", "profile", "name=\"HomeNet\"", "key=clear"]
        );
        b.remove("HomeNet").unwrap();
        assert_eq!(
            b.exec.calls[2],
            ["wlan", "delete", "profile", "name=\"HomeNet\""]
        );
        let odd = Profile {
            os_ref: "a\"b".into(),
            ssid: "a\"b".into(),
        };
        assert_eq!(b.read(&odd).unwrap(), Read::Unavailable);
        assert!(Netsh::<Fake>::listing_is_exact("HomeNet"));
        assert!(!Netsh::<Fake>::listing_is_exact("Café"));
    }
}
