//! Wi-Fi networks of the vault that a device may join on its own, and what
//! changed since they were last given to the system.
//!
//! Shared by every platform that writes networks into its OS (CLI on
//! Windows and Linux, the apps): [`select`] says which Router items
//! qualify, [`Network::fingerprint`] is a stable, secret-free version of
//! each network, and [`diff`] compares the selection with what was applied
//! last ([`Applied`], kept by the caller in a file without any secret).
//!
//! A network qualifies when it has an SSID and a WPA2 or WPA3 personal
//! password. Open, WEP and enterprise networks are never applied: an open
//! or enterprise network joined automatically is an evil-twin target, and
//! WEP is broken.

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::BTreeMap;
use std::fmt;

use aws_lc_rs::digest;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::id::Id;
use crate::model::{FieldValue, Item, ItemType};

/// Security of a network that qualifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Security {
    /// WPA2 personal (pre-shared key). Also the Router menu values `WPA`
    /// and empty, as in a `WIFI:` QR code with `T:WPA`.
    Wpa2Personal,
    /// WPA3 personal (SAE).
    Wpa3Personal,
}

impl Security {
    /// Stable name used in fingerprints and reports.
    pub fn name(self) -> &'static str {
        match self {
            Security::Wpa2Personal => "wpa2-personal",
            Security::Wpa3Personal => "wpa3-personal",
        }
    }
}

/// Why an item was not selected. Counted, never shown with a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Skip {
    /// Not a Router item.
    NotRouter,
    /// In the trash or archived.
    Inactive,
    /// No SSID, or one longer than 32 bytes.
    NoSsid,
    /// No Wi-Fi password.
    NoPassword,
    /// Open network: never joined automatically.
    Open,
    /// WEP: broken, never applied.
    Wep,
    /// Enterprise (802.1X) or a security the model does not know.
    Enterprise,
    /// A password no WPA personal network accepts (8 to 63 printable ASCII
    /// characters, or 64 hexadecimal digits).
    BadPassword,
    /// Another qualifying item has the same SSID and was updated later.
    Duplicate,
}

impl Skip {
    /// Stable code for reports.
    pub fn code(self) -> &'static str {
        match self {
            Skip::NotRouter => "not_router",
            Skip::Inactive => "inactive",
            Skip::NoSsid => "no_ssid",
            Skip::NoPassword => "no_password",
            Skip::Open => "open",
            Skip::Wep => "wep",
            Skip::Enterprise => "enterprise",
            Skip::BadPassword => "bad_password",
            Skip::Duplicate => "duplicate",
        }
    }
}

/// A network the device may join: SSID, pre-shared key, security, hidden
/// flag, and the item it comes from.
#[derive(Clone)]
pub struct Network {
    pub item_id: Id,
    pub ssid: String,
    pub psk: Zeroizing<String>,
    pub security: Security,
    pub hidden: bool,
    /// `updated_at` of the item, Unix nanoseconds: orders duplicates and
    /// enters the fingerprint.
    pub updated_ns: i128,
}

impl fmt::Debug for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Network")
            .field("item_id", &self.item_id)
            .field("ssid", &self.ssid)
            .field("psk", &"[redacted]")
            .field("security", &self.security)
            .field("hidden", &self.hidden)
            .finish()
    }
}

impl Network {
    /// Version of this network: SHA-256 (hex) of the item id, SSID,
    /// security, hidden flag and item `updated_at`. Never derived from the
    /// password (a hash of a Wi-Fi password is cheap to brute force); a
    /// changed password changes `updated_at`, so the version moves too.
    pub fn fingerprint(&self) -> String {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"onepass-wifi-v1\0");
        ctx.update(&self.item_id.0);
        let ssid = self.ssid.as_bytes();
        ctx.update(&(ssid.len() as u64).to_be_bytes());
        ctx.update(ssid);
        ctx.update(self.security.name().as_bytes());
        ctx.update(&[u8::from(self.hidden)]);
        ctx.update(&self.updated_ns.to_be_bytes());
        HEXLOWER.encode(ctx.finish().as_ref())
    }
}

/// Text of field `id` of `item`, if it holds text.
fn text<'a>(item: &'a Item, id: &str) -> Option<&'a str> {
    match &item.field(id)?.value {
        FieldValue::Text(s) | FieldValue::Menu(s) => Some(s.as_str()),
        FieldValue::Password(s) | FieldValue::Concealed(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Security of a Router menu value (or free text from an import).
fn security_of(raw: &str) -> Result<Security, Skip> {
    let s = raw.trim().to_lowercase();
    if ["entreprise", "enterprise", "802.1x", "eap", "radius"]
        .iter()
        .any(|k| s.contains(k))
    {
        return Err(Skip::Enterprise);
    }
    match s.as_str() {
        "" | "wpa" | "wpa2" | "wpa/wpa2" | "wpa2 personnel" | "wpa2 personal" | "wpa2-psk"
        | "wpa2psk" => Ok(Security::Wpa2Personal),
        "wpa3" | "wpa2/wpa3" | "wpa3 personnel" | "wpa3 personal" | "wpa3-sae" | "sae" => {
            Ok(Security::Wpa3Personal)
        }
        "wep" => Err(Skip::Wep),
        "ouvert" | "open" | "aucune" | "aucun" | "none" | "nopass" => Err(Skip::Open),
        _ => Err(Skip::Enterprise),
    }
}

/// Whether `psk` is a WPA personal key: 8 to 63 printable ASCII
/// characters, or 64 hexadecimal digits.
pub fn valid_psk(psk: &str) -> bool {
    let n = psk.len();
    if n == 64 {
        return psk.bytes().all(|b| b.is_ascii_hexdigit());
    }
    (8..=63).contains(&n) && psk.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// The network of `item`, or why it does not qualify.
pub fn classify(item: &Item) -> Result<Network, Skip> {
    if item.item_type != ItemType::Router {
        return Err(Skip::NotRouter);
    }
    if item.trashed_at.is_some() || item.archived {
        return Err(Skip::Inactive);
    }
    let ssid = text(item, "ssid").unwrap_or("");
    if ssid.is_empty() || ssid.len() > 32 {
        return Err(Skip::NoSsid);
    }
    let security = security_of(text(item, "security").unwrap_or(""));
    let psk = text(item, "wifi_password").unwrap_or("");
    // Open first: an open network with a stray password is still open.
    if security == Err(Skip::Open) {
        return Err(Skip::Open);
    }
    if psk.is_empty() {
        return Err(Skip::NoPassword);
    }
    let security = security?;
    if !valid_psk(psk) {
        return Err(Skip::BadPassword);
    }
    let hidden = matches!(
        text(item, "hidden")
            .map(|h| h.trim().to_lowercase())
            .as_deref(),
        Some("oui" | "yes" | "true")
    );
    Ok(Network {
        item_id: item.id,
        ssid: ssid.to_owned(),
        psk: Zeroizing::new(psk.to_owned()),
        security,
        hidden,
        updated_ns: item.updated_at.unix_timestamp_nanos(),
    })
}

/// The networks of a set of items, one per SSID (the latest updated item
/// wins), sorted by SSID, and the count of each reason to skip.
#[derive(Debug, Default)]
pub struct Selection {
    pub networks: Vec<Network>,
    pub skipped: BTreeMap<Skip, u32>,
}

impl Selection {
    /// Skip counts by code, for reports.
    pub fn skipped_codes(&self) -> BTreeMap<&'static str, u32> {
        self.skipped.iter().map(|(k, v)| (k.code(), *v)).collect()
    }
}

/// Select the networks of `items` (see [`classify`]). Items that are not
/// Router items are not counted.
pub fn select<'a>(items: impl IntoIterator<Item = &'a Item>) -> Selection {
    let mut by_ssid: BTreeMap<String, Network> = BTreeMap::new();
    let mut skipped: BTreeMap<Skip, u32> = BTreeMap::new();
    for item in items {
        match classify(item) {
            Ok(n) => {
                let replaced = match by_ssid.get(&n.ssid) {
                    // Latest update wins; equal times keep the lower id.
                    Some(old) => (n.updated_ns, std::cmp::Reverse(n.item_id.0))
                        .gt(&(old.updated_ns, std::cmp::Reverse(old.item_id.0))),
                    None => true,
                };
                *skipped.entry(Skip::Duplicate).or_default() +=
                    u32::from(by_ssid.contains_key(&n.ssid));
                if replaced {
                    by_ssid.insert(n.ssid.clone(), n);
                }
            }
            Err(Skip::NotRouter) => {}
            Err(why) => *skipped.entry(why).or_default() += 1,
        }
    }
    skipped.retain(|_, v| *v > 0);
    Selection {
        networks: by_ssid.into_values().collect(),
        skipped,
    }
}

/// What was given to the system for one SSID: the system's own reference
/// (profile name, connection UUID) and the fingerprint applied. No secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub os_ref: String,
    pub fingerprint: String,
}

/// Changes that bring the system in line with the vault.
#[derive(Debug, Default)]
pub struct Plan<'a> {
    /// Networks the system does not have from us yet.
    pub add: Vec<&'a Network>,
    /// Networks whose fingerprint moved, with the system reference.
    pub update: Vec<(&'a Network, String)>,
    /// SSIDs we applied that left the vault, with the system reference.
    pub remove: Vec<(String, String)>,
    /// Networks already applied with the same fingerprint.
    pub unchanged: usize,
}

impl Plan<'_> {
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.update.is_empty() && self.remove.is_empty()
    }
}

/// Compare the selected networks with what was applied (keyed by SSID).
/// Running the plan and recording each step in `applied` makes the next
/// diff empty: applying is idempotent.
pub fn diff<'a>(networks: &'a [Network], applied: &BTreeMap<String, Applied>) -> Plan<'a> {
    let mut plan = Plan::default();
    for n in networks {
        match applied.get(&n.ssid) {
            None => plan.add.push(n),
            Some(a) if a.fingerprint != n.fingerprint() => {
                plan.update.push((n, a.os_ref.clone()));
            }
            Some(_) => plan.unchanged += 1,
        }
    }
    for (ssid, a) in applied {
        if !networks.iter().any(|n| &n.ssid == ssid) {
            plan.remove.push((ssid.clone(), a.os_ref.clone()));
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::new_item;
    use time::OffsetDateTime;

    fn router(ssid: &str, psk: &str, security: &str) -> Item {
        let mut it = new_item(ItemType::Router, Id([1; 16]), ssid);
        it.id = Id::new();
        for (id, v) in [
            ("ssid", FieldValue::Text(ssid.into())),
            (
                "wifi_password",
                FieldValue::Password(Zeroizing::new(psk.into())),
            ),
            ("security", FieldValue::Menu(security.into())),
        ] {
            it.field_mut(id).unwrap().value = v;
        }
        it
    }

    #[test]
    fn wpa2_and_wpa3_qualify() {
        let n = classify(&router("Home", "correct horse", "WPA2")).unwrap();
        assert_eq!(n.security, Security::Wpa2Personal);
        assert!(!n.hidden);
        let n = classify(&router("Home", "correct horse", "WPA3")).unwrap();
        assert_eq!(n.security, Security::Wpa3Personal);
        // Empty and plain WPA mean a WPA personal key, as in QR codes.
        for s in ["", "WPA", " wpa2 "] {
            assert_eq!(
                classify(&router("H", "12345678", s)).unwrap().security,
                Security::Wpa2Personal
            );
        }
    }

    #[test]
    fn open_wep_enterprise_and_bad_keys_are_skipped() {
        let why = |i: Item| classify(&i).unwrap_err();
        assert_eq!(why(router("Cafe", "", "Ouvert")), Skip::Open);
        assert_eq!(why(router("Cafe", "stray-password", "Ouvert")), Skip::Open);
        assert_eq!(why(router("Old", "12345", "WEP")), Skip::Wep);
        assert_eq!(
            why(router("Corp", "12345678", "WPA2 Entreprise")),
            Skip::Enterprise
        );
        assert_eq!(why(router("Corp", "12345678", "802.1X")), Skip::Enterprise);
        assert_eq!(why(router("Odd", "12345678", "Mystery")), Skip::Enterprise);
        assert_eq!(why(router("Home", "", "WPA2")), Skip::NoPassword);
        assert_eq!(why(router("Home", "short", "WPA2")), Skip::BadPassword);
        assert_eq!(
            why(router("Home", "mot de passe é", "WPA2")),
            Skip::BadPassword
        );
        assert_eq!(why(router("", "12345678", "WPA2")), Skip::NoSsid);
        assert_eq!(
            why(router(&"x".repeat(33), "12345678", "WPA2")),
            Skip::NoSsid
        );
        let mut trashed = router("Home", "12345678", "WPA2");
        trashed.trashed_at = Some(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(why(trashed), Skip::Inactive);
        let login = new_item(ItemType::Login, Id([1; 16]), "x");
        assert_eq!(why(login), Skip::NotRouter);
    }

    #[test]
    fn psk_rules() {
        assert!(valid_psk("12345678"));
        assert!(valid_psk(&"a".repeat(63)));
        assert!(!valid_psk(&"a".repeat(65)));
        assert!(valid_psk(&"0f".repeat(32)));
        assert!(!valid_psk(&"zz".repeat(32)));
        assert!(!valid_psk("1234567"));
        assert!(!valid_psk("tab\there!"));
    }

    #[test]
    fn hidden_flag_is_read() {
        let mut it = router("Hidden", "12345678", "WPA2");
        it.field_mut("hidden").unwrap().value = FieldValue::Menu("oui".into());
        assert!(classify(&it).unwrap().hidden);
    }

    #[test]
    fn duplicates_keep_the_latest_and_are_counted() {
        let mut old = router("Home", "old-password", "WPA2");
        old.updated_at = OffsetDateTime::UNIX_EPOCH;
        let mut new = router("Home", "new-password", "WPA2");
        new.updated_at = OffsetDateTime::UNIX_EPOCH + time::Duration::days(1);
        let other = router("Cafe", "", "Ouvert");
        for order in [[&old, &new, &other], [&new, &old, &other]] {
            let s = select(order);
            assert_eq!(s.networks.len(), 1);
            assert_eq!(s.networks[0].psk.as_str(), "new-password");
            assert_eq!(s.skipped.get(&Skip::Duplicate), Some(&1));
            assert_eq!(s.skipped_codes().get("open"), Some(&1));
        }
    }

    #[test]
    fn fingerprint_is_stable_and_secret_free() {
        let it = router("Home", "password-one", "WPA2");
        let a = classify(&it).unwrap();
        assert_eq!(a.fingerprint(), classify(&it).unwrap().fingerprint());
        assert_eq!(a.fingerprint().len(), 64);
        // The password alone does not enter it...
        let mut same = a.clone();
        same.psk = Zeroizing::new("password-two".into());
        assert_eq!(a.fingerprint(), same.fingerprint());
        // ...the item update time, the SSID, the security and hidden do.
        for change in [
            |n: &mut Network| n.updated_ns += 1,
            |n: &mut Network| n.ssid.push('2'),
            |n: &mut Network| n.security = Security::Wpa3Personal,
            |n: &mut Network| n.hidden = true,
        ] {
            let mut b = a.clone();
            change(&mut b);
            assert_ne!(a.fingerprint(), b.fingerprint());
        }
        assert!(!format!("{a:?}").contains("password-one"));
    }

    #[test]
    fn diff_adds_updates_removes_then_converges() {
        let home = classify(&router("Home", "12345678", "WPA2")).unwrap();
        let cafe = classify(&router("Cafe", "abcdefgh", "WPA3")).unwrap();
        let networks = vec![cafe.clone(), home.clone()];
        let mut applied: BTreeMap<String, Applied> = BTreeMap::new();
        applied.insert(
            "Home".into(),
            Applied {
                os_ref: "home-ref".into(),
                fingerprint: "old".into(),
            },
        );
        applied.insert(
            "Gone".into(),
            Applied {
                os_ref: "gone-ref".into(),
                fingerprint: "x".into(),
            },
        );
        let plan = diff(&networks, &applied);
        assert_eq!(plan.add.len(), 1);
        assert_eq!(plan.add[0].ssid, "Cafe");
        assert_eq!(plan.update.len(), 1);
        assert_eq!(plan.update[0].1, "home-ref");
        assert_eq!(
            plan.remove,
            vec![("Gone".to_owned(), "gone-ref".to_owned())]
        );
        // Record the plan as a caller would: the next diff is empty.
        applied.remove("Gone");
        for n in &networks {
            applied.insert(
                n.ssid.clone(),
                Applied {
                    os_ref: format!("{}-ref", n.ssid),
                    fingerprint: n.fingerprint(),
                },
            );
        }
        let again = diff(&networks, &applied);
        assert!(again.is_empty());
        assert_eq!(again.unchanged, 2);
    }
}
