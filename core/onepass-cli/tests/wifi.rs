//! End-to-end tests of `onepass wifi` against the fake system of debug
//! builds (`ONEPASS_DEV_WIFI_FAKE`, a JSON file of profiles).

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use serde_json::{Value, json};

const SECRET_STORE: &str = concat!("dir:", env!("CARGO_TARGET_TMPDIR"), "/secret-store-wifi");
const PASSWORD: &str = "correct horse battery";

struct Env<'a> {
    data: &'a Path,
    config: &'a Path,
    fake: &'a Path,
}

impl Env<'_> {
    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("onepass").unwrap();
        c.env("ONEPASS_DEV_ALLOW_ENV_PASSWORD", "1")
            .env("ONEPASS_PASSWORD", PASSWORD)
            .env("ONEPASS_DEV_FAST_KDF", "1")
            .env("ONEPASS_DEV_SECRET_STORE", SECRET_STORE)
            .env("ONEPASS_DEV_WIFI_FAKE", self.fake)
            .env("XDG_CONFIG_HOME", self.config)
            .arg("--data-dir")
            .arg(self.data);
        c
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.cmd().args(args).output().unwrap();
        let stdout = String::from_utf8(o.stdout).unwrap();
        let stderr = String::from_utf8(o.stderr).unwrap();
        assert!(o.status.success(), "{args:?}: {stderr}");
        for secret in [
            "home-password-1",
            "home-password-2",
            "attic-password",
            "bus-password",
        ] {
            assert!(!stdout.contains(secret) || args.first() == Some(&"read"));
            assert!(!stderr.contains(secret));
        }
        stdout
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        serde_json::from_str(self.ok(&a).trim()).unwrap()
    }

    fn profiles(&self) -> Vec<Value> {
        let v: Value = serde_json::from_slice(&fs::read(self.fake).unwrap()).unwrap();
        v["profiles"].as_array().unwrap().clone()
    }

    fn profile(&self, ssid: &str) -> Option<Value> {
        self.profiles().into_iter().find(|p| p["ssid"] == ssid)
    }

    fn add_profile(&self, p: Value) {
        let mut v: Value = serde_json::from_slice(&fs::read(self.fake).unwrap()).unwrap();
        v["profiles"].as_array_mut().unwrap().push(p);
        fs::write(self.fake, serde_json::to_vec(&v).unwrap()).unwrap();
    }
}

fn router(env: &Env<'_>, title: &str, password: &str, security: &str) {
    let ssid = format!("ssid={title}");
    let pw = format!("wifi_password={password}");
    let sec = format!("security={security}");
    let mut args = vec![
        "item", "create", "router", "--title", title, "--field", &ssid,
    ];
    if !password.is_empty() {
        args.extend(["--field", &pw]);
    }
    args.extend(["--field", &sec]);
    env.ok(&args);
}

fn profile(os_ref: &str, ssid: &str, psk: &str, auth: &str) -> Value {
    json!({ "os_ref": os_ref, "ssid": ssid, "psk": psk, "auth": auth, "hidden": false })
}

#[test]
fn sync_import_watch_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let config = tmp.path().join("config");
    let fake = tmp.path().join("system.json");
    let env = Env {
        data: &data,
        config: &config,
        fake: &fake,
    };
    fs::write(
        &fake,
        serde_json::to_vec(&json!({
            "next": 0,
            "profiles": [
                profile("sys-1", "Attic", "attic-password", "wpa2"),
                profile("sys-2", "Guest", "", "open"),
                profile("sys-3", "Office", "office-system-pw", "wpa3"),
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    env.ok(&["account", "create"]);
    router(&env, "Home", "home-password-1", "WPA2");
    router(&env, "Office", "office-vault-pw", "WPA3");
    router(&env, "Cafe", "", "Ouvert");
    router(&env, "Old", "12345", "WEP");

    // First sync: Home goes in; Office was already in the system and is
    // left alone; open and WEP are never applied.
    let r = env.json(&["wifi", "sync"]);
    assert_eq!(r["added"], 1, "{r}");
    assert_eq!(r["kept_system"], 1);
    assert_eq!(r["skipped"]["open"], 1);
    assert_eq!(r["skipped"]["wep"], 1);
    let home = env.profile("Home").unwrap();
    assert_eq!(home["psk"], "home-password-1");
    assert_eq!(home["auth"], "wpa2");
    assert_eq!(env.profile("Office").unwrap()["psk"], "office-system-pw");

    // Idempotent.
    let r = env.json(&["wifi", "sync"]);
    assert_eq!(
        (r["added"].clone(), r["unchanged"].clone()),
        (json!(0), json!(1))
    );
    assert_eq!(env.profiles().len(), 4);

    // A new password in the vault reaches the system.
    env.ok(&[
        "item",
        "edit",
        "Home",
        "--field",
        "wifi_password=home-password-2",
    ]);
    let r = env.json(&["wifi", "sync"]);
    assert_eq!(r["updated"], 1, "{r}");
    assert_eq!(env.profile("Home").unwrap()["psk"], "home-password-2");

    // Import: Attic comes in; Guest is open, Office already in the vault,
    // Home is ours.
    let r = env.json(&["wifi", "import"]);
    assert_eq!(r["imported"], 1, "{r}");
    assert_eq!(r["import_skipped"]["not_personal"], 1);
    assert_eq!(r["import_skipped"]["already_in_vault"], 1);
    assert_eq!(
        env.ok(&["read", "onepass://Personnel/Attic/wifi_password"]),
        "attic-password"
    );
    let r = env.json(&["wifi", "import"]);
    assert_eq!(r["imported"], 0);

    // The state file has no key.
    let state = fs::read_to_string(config.join("onepass").join("wifi-state.json")).unwrap();
    assert!(state.contains("Home"));
    for secret in ["home-password", "attic-password", "office-"] {
        assert!(!state.contains(secret));
    }

    // Deleted from the vault: removed from the system, not imported back.
    env.ok(&["item", "delete", "Home"]);
    let r = env.json(&["wifi", "sync"]);
    assert_eq!(r["removed"], 1, "{r}");
    assert!(env.profile("Home").is_none());

    // Watch: a network the system just saved goes to the vault, without a
    // prompt; one round with nothing new changes nothing.
    env.add_profile(profile("sys-9", "Bus", "bus-password", "wpa2"));
    env.ok(&["wifi", "watch", "--once"]);
    assert_eq!(
        env.ok(&["read", "onepass://Personnel/Bus/wifi_password"]),
        "bus-password"
    );
    let before = env.profiles();
    env.ok(&["wifi", "watch", "--once"]);
    assert_eq!(env.profiles(), before);

    // Watch also syncs: a router created in the vault reaches the system.
    router(&env, "Garden", "garden-pass-1", "WPA2");
    env.ok(&["wifi", "watch", "--once"]);
    assert_eq!(env.profile("Garden").unwrap()["psk"], "garden-pass-1");
}

#[test]
fn locked_watch_notes_networks_for_the_next_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    let config = tmp.path().join("config");
    let fake = tmp.path().join("system.json");
    let env = Env {
        data: &data,
        config: &config,
        fake: &fake,
    };
    fs::write(&fake, br#"{"next":0,"profiles":[]}"#).unwrap();
    env.ok(&["account", "create"]);
    // A first round marks what is there.
    env.ok(&["wifi", "watch", "--once"]);
    env.add_profile(profile("sys-5", "Train", "train-password", "wpa2"));
    // No password anywhere: the watch runs locked and only notes the
    // network (its key stays in the system).
    let o = env
        .cmd()
        .env_remove("ONEPASS_PASSWORD")
        .args(["wifi", "watch", "--once"])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("running locked"));
    let state = fs::read_to_string(config.join("onepass").join("wifi-state.json")).unwrap();
    assert!(state.contains("sys-5"));
    assert!(!state.contains("train-password"));
    // The next unlocked sync imports it.
    let r = env.json(&["wifi", "sync"]);
    assert_eq!(r["imported"], 1, "{r}");
    assert_eq!(
        env.ok(&["read", "onepass://Personnel/Train/wifi_password"]),
        "train-password"
    );
}
