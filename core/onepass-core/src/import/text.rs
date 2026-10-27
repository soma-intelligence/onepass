//! Text sources: `otpauth://` URI lists, `WIFI:` QR strings, and the
//! parsers of the `networksetup` outputs used by the Wi-Fi keychain import
//! (spec 4.3 and 4.5).

use std::fmt;

use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::id::Id;
use crate::model::{Item, ItemType, new_item};
use crate::totp::{TotpAlgorithm, TotpConfig, parse_migration, parse_otpauth};

use super::build::{Draft, otpauth_from_parts};
use super::limits::{MAX_INPUT, MAX_RECORDS};
use super::{Import, Warning};

/// Most networks kept from `networksetup -listpreferredwirelessnetworks`.
const MAX_PREFERRED: usize = 10_000;

/// A Wi-Fi network. `security` is one of the Router menu values: `WPA3`,
/// `WPA2`, `WPA`, `WEP`, `ouvert`.
#[derive(Clone)]
pub struct WifiNetwork {
    pub ssid: String,
    pub password: Option<Zeroizing<String>>,
    pub security: String,
    pub hidden: bool,
}

impl fmt::Debug for WifiNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WifiNetwork")
            .field("ssid", &self.ssid)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("security", &self.security)
            .field("hidden", &self.hidden)
            .finish()
    }
}

/// Whether `n` is an open network that still carries a password (QR code
/// `T:nopass` with a `P:`): the password then goes to `imported`.
fn open_with_password(n: &WifiNetwork) -> bool {
    n.security == "ouvert" && n.password.is_some()
}

/// Router draft for a network: SSID, password, security and hidden flag.
/// The password of an open network is kept, masked, in `imported`.
pub(crate) fn router_draft(n: &WifiNetwork) -> Draft {
    let mut d = Draft::new(ItemType::Router);
    d.title(&n.ssid);
    d.set("ssid", &n.ssid);
    match &n.password {
        Some(p) if open_with_password(n) => d.extra("Mot de passe Wi-Fi", p, true),
        Some(p) => d.set("wifi_password", p),
        None => {}
    }
    d.set("security", &n.security);
    d.set("hidden", if n.hidden { "oui" } else { "non" });
    d
}

/// A Router item for `n`, titled with the SSID, in the provisional vault
/// `Id([0; 16])`. Always valid: `Draft::finish` applies the fallbacks.
pub fn router_item(n: &WifiNetwork) -> Item {
    let mut out = Import::default();
    router_draft(n).finish(0, &mut out);
    match out.items.pop() {
        Some(i) => i.item,
        None => new_item(ItemType::Router, Id([0; 16]), &n.ssid),
    }
}

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// `\x` is `x`; a lone trailing backslash is dropped (callers reject it
/// earlier).
fn unescape(raw: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(raw.len()));
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `WIFI:` QR string: `S:`, `T:`, `P:`, `H:` pairs in any order, ended by
/// `;;`. Escapes: backslash before `; , : \ "`. An empty `T:` with a
/// password is `WPA`; `T:nopass` is `ouvert` and keeps a `P:` password,
/// which the importer moves to `imported` (warning `field_moved`).
pub fn parse_wifi_qr(line: &str) -> Result<WifiNetwork> {
    const BAD: Error = Error::InvalidFormat("wifi qr");
    let t = line.trim();
    if !starts_with_ci(t, "WIFI:") {
        return Err(BAD);
    }
    let rest = t.get(5..).ok_or(BAD)?;
    // Split on unescaped `;`, keeping the escapes for `unescape`.
    let mut segments: Vec<Zeroizing<String>> = Vec::new();
    let mut seg = Zeroizing::new(String::new());
    let mut escaped = false;
    for c in rest.chars() {
        if escaped {
            seg.push('\\');
            seg.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ';' {
            segments.push(std::mem::take(&mut seg));
        } else {
            seg.push(c);
        }
    }
    if escaped {
        return Err(BAD);
    }
    if !seg.is_empty() {
        segments.push(seg);
    }
    let mut ssid = None;
    let mut password = None;
    let mut kind = Zeroizing::new(String::new());
    let mut hidden = false;
    for seg in &segments {
        let Some((key, value)) = seg.split_once(':') else {
            continue;
        };
        match key.trim().to_ascii_uppercase().as_str() {
            "S" => ssid = Some(unescape(value)),
            "P" => password = Some(unescape(value)),
            "T" => kind = unescape(value),
            "H" => hidden = unescape(value).trim().eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    let ssid = ssid.filter(|s| !s.is_empty()).ok_or(BAD)?;
    let password = password.filter(|p| !p.is_empty());
    let security = match kind.trim().to_ascii_uppercase().as_str() {
        "" if password.is_some() => "WPA",
        "" | "NOPASS" => "ouvert",
        "WPA3" | "SAE" => "WPA3",
        "WPA2" => "WPA2",
        "WPA" => "WPA",
        "WEP" => "WEP",
        _ => return Err(BAD),
    };
    Ok(WifiNetwork {
        ssid: ssid.to_string(),
        password,
        security: security.to_owned(),
        hidden,
    })
}

/// The file as UTF-8 text, BOM dropped, within the input cap.
fn as_text(b: &[u8]) -> Result<&str> {
    if b.len() > MAX_INPUT {
        return Err(Error::InvalidFormat("import file too large"));
    }
    let b = b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b);
    std::str::from_utf8(b).map_err(|_| Error::InvalidFormat("text file is not utf-8"))
}

fn unsupported(entry: u32, out: &mut Import) {
    out.skipped += 1;
    out.warnings.push(Warning {
        entry,
        code: "unsupported_entry",
    });
}

/// One `WIFI:` string per line. An invalid line gives an
/// `unsupported_entry` warning, not an error for the file.
pub(crate) fn parse_wifi_qr_lines(b: &[u8]) -> Result<Import> {
    let text = as_text(b)?;
    let mut out = Import::default();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_RECORDS {
            return Err(Error::InvalidFormat("too many lines"));
        }
        if line.trim().is_empty() {
            continue;
        }
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        match parse_wifi_qr(line) {
            Ok(n) => {
                if open_with_password(&n) {
                    out.warnings.push(Warning {
                        entry,
                        code: "field_moved",
                    });
                }
                router_draft(&n).finish(entry, &mut out);
            }
            Err(_) => unsupported(entry, &mut out),
        }
    }
    Ok(out)
}

/// Login draft for one TOTP configuration: the URI is rebuilt from its
/// parts so every source (plain or migration) ends in the same form.
fn totp_login(cfg: &TotpConfig) -> Draft {
    let secret = Zeroizing::new(BASE32_NOPAD.encode(&cfg.secret));
    let algorithm = match cfg.algorithm {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    };
    let digits = if cfg.steam { 6 } else { cfg.digits };
    let base = Zeroizing::new(otpauth_from_parts(
        &secret,
        cfg.issuer.as_deref(),
        cfg.account.as_deref(),
        algorithm,
        digits,
        cfg.period,
    ));
    const STEAM: &str = "&encoder=steam";
    let mut uri = Zeroizing::new(String::with_capacity(base.len() + STEAM.len()));
    uri.push_str(&base);
    if cfg.steam {
        uri.push_str(STEAM);
    }
    fn named(o: &Option<String>) -> Option<&str> {
        o.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }
    let (issuer, account) = (named(&cfg.issuer), named(&cfg.account));
    let mut d = Draft::new(ItemType::Login);
    d.title(issuer.or(account).unwrap_or(""));
    d.set("username", account.or(issuer).unwrap_or(""));
    d.set("totp", &uri);
    d
}

/// One `otpauth://` or `otpauth-migration://` URI per line. Login title is
/// the issuer, else the account; username is the account, else the issuer.
/// A blank line is ignored; an invalid one gives `unsupported_entry`.
pub(crate) fn parse_otpauth_lines(b: &[u8]) -> Result<Import> {
    let text = as_text(b)?;
    let mut out = Import::default();
    for (index, line) in text.lines().enumerate() {
        if index >= MAX_RECORDS {
            return Err(Error::InvalidFormat("too many lines"));
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = u32::try_from(index).unwrap_or(u32::MAX);
        let configs = if starts_with_ci(line, "otpauth-migration://") {
            parse_migration(line)
        } else if starts_with_ci(line, "otpauth://") {
            parse_otpauth(line).map(|c| vec![c])
        } else {
            Err(Error::InvalidFormat("otpauth line"))
        };
        match configs {
            Ok(list) => {
                for cfg in &list {
                    totp_login(cfg).finish(entry, &mut out);
                }
            }
            Err(_) => unsupported(entry, &mut out),
        }
    }
    Ok(out)
}

/// Device of the `networksetup -listallhardwareports` block whose
/// `Hardware Port:` is `Wi-Fi` or `AirPort`.
pub fn parse_hardware_ports(out: &str) -> Option<String> {
    let mut wifi_block = false;
    for line in out.lines() {
        let line = line.trim();
        if let Some(port) = line.strip_prefix("Hardware Port:") {
            let port = port.trim();
            wifi_block = port == "Wi-Fi" || port == "AirPort";
        } else if let Some(dev) = line.strip_prefix("Device:") {
            let dev = dev.trim();
            if wifi_block && !dev.is_empty() {
                return Some(dev.to_owned());
            }
        }
    }
    None
}

/// Networks of `networksetup -listpreferredwirelessnetworks <dev>`: every
/// line after the header, leading tab or spaces removed, blanks dropped,
/// 10 000 at most.
pub fn parse_preferred_networks(out: &str) -> Vec<String> {
    out.lines()
        .skip(1)
        .map(|l| l.trim_start_matches(['\t', ' ']))
        .filter(|l| !l.trim().is_empty())
        .take(MAX_PREFERRED)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FieldValue, validate};
    use crate::totp::parse_otpauth;

    const OTP: &[u8] = include_bytes!("../../tests/fixtures/import/otpauth.txt");
    const QR: &[u8] = include_bytes!("../../tests/fixtures/import/wifi-qr.txt");

    fn text(item: &Item, id: &str) -> Option<String> {
        match &item.field(id)?.value {
            FieldValue::Text(s) | FieldValue::Menu(s) | FieldValue::Url(s) => Some(s.clone()),
            FieldValue::Password(s) | FieldValue::Concealed(s) | FieldValue::Otp(s) => {
                Some(s.to_string())
            }
            _ => None,
        }
    }

    #[test]
    fn otpauth_lines() {
        let imp = parse_otpauth_lines(OTP).unwrap();
        let t: Vec<&str> = imp.items.iter().map(|i| i.item.title.as_str()).collect();
        assert_eq!(t, ["Example", "Acme", "Corp", "Steam", "GitHub"]);
        // Invalid line: warned and counted, not fatal.
        assert_eq!(imp.skipped, 1);
        assert_eq!(
            imp.warnings,
            [Warning {
                entry: 5,
                code: "unsupported_entry"
            }]
        );
        let first = &imp.items[0].item;
        assert_eq!(first.item_type, ItemType::Login);
        assert_eq!(
            text(first, "username").as_deref(),
            Some("alice@example.com")
        );
        let uri = text(first, "totp").unwrap();
        let cfg = parse_otpauth(&uri).unwrap();
        assert_eq!((cfg.digits, cfg.period), (8, 60));
        assert_eq!(cfg.issuer.as_deref(), Some("Example"));
        // Issuer taken from the label when the parameter is absent.
        let acme = parse_otpauth(&text(&imp.items[1].item, "totp").unwrap()).unwrap();
        assert_eq!(acme.issuer.as_deref(), Some("Acme"));
        // No label issuer: the parameter wins; username is the account.
        assert_eq!(
            text(&imp.items[2].item, "username").as_deref(),
            Some("carol@example.com")
        );
        for i in &imp.items {
            validate(&i.item).unwrap();
            assert_eq!(i.item.vault_id.0, [0; 16]);
        }
    }

    #[test]
    fn otpauth_steam_roundtrips() {
        let imp = parse_otpauth_lines(OTP).unwrap();
        let uri = text(&imp.items[3].item, "totp").unwrap();
        assert!(parse_otpauth(&uri).unwrap().steam);
    }

    #[test]
    fn otpauth_issuer_only_uses_it_as_username() {
        let imp =
            parse_otpauth_lines(b"otpauth://totp/?secret=JBSWY3DPEHPK3PXP&issuer=Solo\n").unwrap();
        let i = &imp.items[0].item;
        assert_eq!(i.title, "Solo");
        assert_eq!(text(i, "username").as_deref(), Some("Solo"));
    }

    #[test]
    fn migration_line() {
        let imp = parse_otpauth_lines(OTP).unwrap();
        let gh = &imp.items[4].item;
        assert_eq!(gh.title, "GitHub");
        assert_eq!(text(gh, "username").as_deref(), Some("quentin"));
        let cfg = parse_otpauth(&text(gh, "totp").unwrap()).unwrap();
        assert_eq!(&cfg.secret[..], b"12345678901234567890");
    }

    #[test]
    fn otpauth_rejects_non_utf8_and_oversized_input() {
        assert!(parse_otpauth_lines(&[0xff, 0xfe]).is_err());
        assert!(parse_wifi_qr_lines(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn wifi_qr_escapes() {
        let n = parse_wifi_qr(r"WIFI:T:WPA;S:my\;net;P:p\:w\\d;H:true;;").unwrap();
        assert_eq!(n.ssid, "my;net");
        assert_eq!(n.password.as_deref().map(String::as_str), Some(r"p:w\d"));
        assert_eq!(n.security, "WPA");
        assert!(n.hidden);
        let n = parse_wifi_qr(r#"WIFI:S:a\,b\"c;P:x;;"#).unwrap();
        assert_eq!(n.ssid, r#"a,b"c"#);
        assert!(!n.hidden);
    }

    #[test]
    fn wifi_qr_security_values() {
        let sec = |t: &str| parse_wifi_qr(&format!("WIFI:S:n;T:{t};P:x;;")).map(|n| n.security);
        assert_eq!(sec("WPA3").unwrap(), "WPA3");
        assert_eq!(sec("SAE").unwrap(), "WPA3");
        assert_eq!(sec("WPA2").unwrap(), "WPA2");
        assert_eq!(sec("wep").unwrap(), "WEP");
        assert!(sec("bogus").is_err());
    }

    #[test]
    fn wifi_qr_nopass_is_open() {
        let n = parse_wifi_qr("WIFI:S:Cafe;T:nopass;;").unwrap();
        assert_eq!(n.security, "ouvert");
        assert!(n.password.is_none());
        let n = parse_wifi_qr("WIFI:S:Cafe;;").unwrap();
        assert_eq!(n.security, "ouvert");
        assert!(parse_wifi_qr("WIFI:T:WPA;P:x;;").is_err());
        assert!(parse_wifi_qr("HTTP:S:x;;").is_err());
        assert!(parse_wifi_qr(r"WIFI:S:bad\").is_err());
    }

    #[test]
    fn wifi_qr_nopass_with_password_keeps_it_in_imported() {
        let imp = parse_wifi_qr_lines(b"WIFI:S:Cafe;T:nopass;P:Invented-1;;\n").unwrap();
        let it = &imp.items[0].item;
        validate(it).unwrap();
        assert_eq!(text(it, "security").as_deref(), Some("ouvert"));
        assert_eq!(text(it, "wifi_password"), None);
        let moved = it
            .sections
            .iter()
            .filter(|s| s.id == "imported")
            .flat_map(|s| s.fields.iter())
            .find(|f| f.label == "Mot de passe Wi-Fi")
            .map(|f| f.value.clone());
        assert_eq!(
            moved,
            Some(FieldValue::Concealed(Zeroizing::new("Invented-1".into())))
        );
        let codes: Vec<(u32, &str)> = imp.warnings.iter().map(|w| (w.entry, w.code)).collect();
        assert_eq!(codes, [(0, "field_moved")]);
    }

    #[test]
    fn wifi_qr_empty_type_with_password_is_wpa() {
        let n = parse_wifi_qr("WIFI:S:Home;T:;P:Invented-2;;").unwrap();
        assert_eq!(n.security, "WPA");
        assert_eq!(
            n.password.as_deref().map(String::as_str),
            Some("Invented-2")
        );
    }

    #[test]
    fn wifi_qr_lines_file() {
        let imp = parse_wifi_qr_lines(QR).unwrap();
        let t: Vec<&str> = imp.items.iter().map(|i| i.item.title.as_str()).collect();
        assert_eq!(
            t,
            ["HomeNet-Test", "my;net", "CafeOpen-Test", "Wpa3Net-Test"]
        );
        assert_eq!(imp.skipped, 2);
        let codes: Vec<(u32, &str)> = imp.warnings.iter().map(|w| (w.entry, w.code)).collect();
        assert_eq!(codes, [(5, "unsupported_entry"), (6, "unsupported_entry")]);
        let hidden = &imp.items[1].item;
        assert_eq!(text(hidden, "hidden").as_deref(), Some("oui"));
        assert_eq!(text(hidden, "wifi_password").as_deref(), Some(r"p:w\d"));
    }

    #[test]
    fn router_item_is_valid() {
        let n = WifiNetwork {
            ssid: "Net".into(),
            password: Some(Zeroizing::new("pw".into())),
            security: "WPA3".into(),
            hidden: false,
        };
        let item = router_item(&n);
        validate(&item).unwrap();
        assert_eq!(item.item_type, ItemType::Router);
        assert_eq!(item.title, "Net");
        assert_eq!(item.vault_id.0, [0; 16]);
        assert_eq!(text(&item, "ssid").as_deref(), Some("Net"));
        assert_eq!(text(&item, "security").as_deref(), Some("WPA3"));
        assert_eq!(text(&item, "hidden").as_deref(), Some("non"));
        let open = WifiNetwork {
            ssid: "Open".into(),
            password: None,
            security: "ouvert".into(),
            hidden: false,
        };
        validate(&router_item(&open)).unwrap();
    }

    #[test]
    fn wifi_debug_masks_the_password() {
        let n = parse_wifi_qr("WIFI:S:n;T:WPA;P:hunter2;;").unwrap();
        let d = format!("{n:?}");
        assert!(!d.contains("hunter2"));
        assert!(d.contains("[redacted]"));
    }

    #[test]
    fn hardware_ports_finds_wifi() {
        let out = "\nHardware Port: Ethernet\nDevice: en5\nEthernet Address: aa:bb\n\n\
                   Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: cc:dd\n\n\
                   Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n";
        assert_eq!(parse_hardware_ports(out).as_deref(), Some("en0"));
        let old = "Hardware Port: AirPort\nDevice: en1\n";
        assert_eq!(parse_hardware_ports(old).as_deref(), Some("en1"));
        assert_eq!(
            parse_hardware_ports("Hardware Port: Ethernet\nDevice: en5\n"),
            None
        );
        assert_eq!(parse_hardware_ports(""), None);
    }

    #[test]
    fn preferred_networks_list() {
        let out = "Preferred networks on en0:\n\tHomeNet-Test\n\tCafe Free\n\n  Office\r\n";
        assert_eq!(
            parse_preferred_networks(out),
            ["HomeNet-Test", "Cafe Free", "Office"]
        );
        assert!(parse_preferred_networks("Preferred networks on en0:\n").is_empty());
        assert!(parse_preferred_networks("").is_empty());
        let mut big = String::from("Preferred networks on en0:\n");
        for i in 0..10_050 {
            big.push_str(&format!("\tnet{i}\n"));
        }
        assert_eq!(parse_preferred_networks(&big).len(), 10_000);
    }
}
