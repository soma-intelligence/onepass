//! `onepass-mcp install` and `uninstall` against a temporary home, for the
//! four clients. Nothing here touches the real home: every command gets
//! `--home <tempdir>` and a `HOME` that points into the tempdir too.
// Helpers of the Unix-only tests below are unused on Windows.
#![cfg_attr(not(unix), allow(unused_imports, dead_code))]
use serde_json::Value;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_onepass-mcp");

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Json,
    Toml,
}

struct Client {
    name: &'static str,
    path: &'static str,
    format: Format,
}

const CLIENTS: [Client; 4] = [
    Client {
        name: "claude-code",
        path: ".claude.json",
        format: Format::Json,
    },
    Client {
        name: "claude-desktop",
        path: "Library/Application Support/Claude/claude_desktop_config.json",
        format: Format::Json,
    },
    Client {
        name: "codex",
        path: ".codex/config.toml",
        format: Format::Toml,
    },
    Client {
        name: "cursor",
        path: ".cursor/mcp.json",
        format: Format::Json,
    },
];

fn home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn relay_path() -> String {
    fs::canonicalize(BIN).unwrap().to_str().unwrap().to_owned()
}

fn default_socket(home: &Path) -> String {
    home.join("Library/Containers/me.somalabs.onepass/Data/.onepass/mcp.sock")
        .to_str()
        .unwrap()
        .to_owned()
}

fn run(sub: &str, home: &Path, client: &str, extra: &[&str]) -> Output {
    Command::new(BIN)
        .arg(sub)
        .args(["--client", client, "--home"])
        .arg(home)
        .args(extra)
        .env("HOME", home)
        .output()
        .unwrap()
}

fn ok(o: &Output) {
    assert!(
        o.status.success(),
        "failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn file_of(home: &Path, c: &Client) -> PathBuf {
    home.join(c.path)
}

fn write_file(home: &Path, c: &Client, text: &str) -> PathBuf {
    let p = file_of(home, c);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, text).unwrap();
    p
}

/// The `onepass` entry of a client file as (command, args).
fn entry(path: &Path, c: &Client) -> Option<(String, Vec<String>)> {
    let text = fs::read_to_string(path).unwrap();
    match c.format {
        Format::Json => {
            let v: Value = serde_json::from_str(&text).unwrap();
            let e = v.get("mcpServers")?.get("onepass")?;
            Some((
                e["command"].as_str().unwrap().to_owned(),
                e["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_owned())
                    .collect(),
            ))
        }
        Format::Toml => {
            let d: toml_edit::DocumentMut = text.parse().unwrap();
            let e = d.get("mcp_servers")?.get("onepass")?;
            Some((
                e["command"].as_str().unwrap().to_owned(),
                e["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_owned())
                    .collect(),
            ))
        }
    }
}

/// A file that already holds another server, in the client's own format.
fn with_other(c: &Client) -> String {
    match c.format {
        Format::Json => "{\n  \"theme\": \"dark\",\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"/usr/bin/other\",\n      \"args\": [\"-x\"]\n    }\n  },\n  \"tail\": 1.50\n}\n".to_owned(),
        Format::Toml => "model = \"x\"\n\n[mcp_servers.other]\ncommand = \"/usr/bin/other\"\nargs = [\"-x\"]\n".to_owned(),
    }
}

fn has_other(path: &Path, c: &Client) -> bool {
    let text = fs::read_to_string(path).unwrap();
    match c.format {
        Format::Json => {
            let v: Value = serde_json::from_str(&text).unwrap();
            v["mcpServers"]["other"]["command"] == "/usr/bin/other" && v["theme"] == "dark"
        }
        Format::Toml => {
            let d: toml_edit::DocumentMut = text.parse().unwrap();
            d["mcp_servers"]["other"]["command"].as_str() == Some("/usr/bin/other")
                && d["model"].as_str() == Some("x")
        }
    }
}

#[test]
// Unix only: compares the default socket, a path in the Mac app's
// container written with forward slashes.
#[cfg(unix)]
fn install_creates_file() {
    for c in &CLIENTS {
        let h = home();
        let o = run("install", h.path(), c.name, &[]);
        ok(&o);
        let (cmd, args) = entry(&file_of(h.path(), c), c).unwrap_or_else(|| panic!("{}", c.name));
        assert_eq!(cmd, relay_path(), "{}", c.name);
        assert_eq!(
            args,
            ["--socket".to_owned(), default_socket(h.path())],
            "{}",
            c.name
        );
    }
}

#[test]
fn install_keeps_other_servers() {
    for c in &CLIENTS {
        let h = home();
        let p = write_file(h.path(), c, &with_other(c));
        ok(&run("install", h.path(), c.name, &[]));
        assert!(has_other(&p, c), "{}", c.name);
        assert!(entry(&p, c).is_some(), "{}", c.name);
        // Everything that was there is still there, byte for byte.
        let after = fs::read_to_string(&p).unwrap();
        assert!(
            after.contains("\"tail\": 1.50") || c.format == Format::Toml,
            "{}",
            c.name
        );
    }
}

#[test]
fn install_keeps_toml_comments_and_order() {
    let c = &CLIENTS[2];
    let h = home();
    let original = "# my codex config\nmodel = \"gpt-x\" # the model\n\n# servers\n[mcp_servers.zeta]\ncommand = \"z\" # last alphabetically\nargs = [ \"a\",\n  \"b\" ]\n\n[mcp_servers.alpha]\ncommand = \"a\"\n\n[profiles.fast]\nmodel = \"y\"\n# end of file comment\n";
    let p = write_file(h.path(), c, original);
    ok(&run("install", h.path(), c.name, &[]));
    let after = fs::read_to_string(&p).unwrap();
    // toml_edit puts the new table after the other mcp_servers tables: every
    // original line is still there, in the same order, comments included.
    let mut rest = after.lines();
    for line in original.lines() {
        assert!(rest.any(|l| l == line), "lost or moved {line:?}:\n{after}");
    }
    assert!(entry(&p, c).is_some());
    // And uninstall gives the exact original back.
    ok(&run("uninstall", h.path(), c.name, &[]));
    assert_eq!(fs::read_to_string(&p).unwrap(), original);
}

#[test]
fn install_large_claude_json_only_touches_onepass() {
    let c = &CLIENTS[0];
    let h = home();
    // About 5 MB in the style of ~/.claude.json: many projects, odd numbers,
    // escapes, strings that look like keys.
    let mut s = String::from("{\n  \"numStartups\": 42,\n  \"projects\": {\n");
    let n = 9000;
    for i in 0..n {
        s.push_str(&format!(
            "    \"/Users/a/p{i}\": {{\n      \"allowedTools\": [],\n      \"history\": [\"\\\"mcpServers\\\": {{\", \"caf\\u00e9 \\\\ }}\"],\n      \"cost\": 1.0e-3,\n      \"mcpServers\": {{ \"x{i}\": {{ \"command\": \"c\" }} }},\n      \"note\": \"{}\"\n    }}{}\n",
            "x".repeat(380),
            if i + 1 < n { "," } else { "" }
        ));
    }
    s.push_str("  },\n  \"mcpServers\": {\n    \"other\": {\n      \"type\": \"stdio\",\n      \"command\": \"/usr/bin/other\",\n      \"args\": [],\n      \"env\": {}\n    }\n  },\n  \"last\": true\n}\n");
    assert!(s.len() > 5_000_000, "{}", s.len());
    let p = write_file(h.path(), c, &s);
    ok(&run("install", h.path(), c.name, &[]));
    let after = fs::read_to_string(&p).unwrap();
    assert!(entry(&p, c).is_some());
    // The new text is the old one plus one contiguous insertion.
    let pre = s
        .bytes()
        .zip(after.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    let suf = s
        .bytes()
        .rev()
        .zip(after.bytes().rev())
        .take_while(|(a, b)| a == b)
        .count();
    assert!(pre + suf >= s.len(), "more than the onepass entry changed");
    // And removing it gives the file back byte for byte.
    ok(&run("uninstall", h.path(), c.name, &[]));
    assert_eq!(fs::read_to_string(&p).unwrap(), s);
}

#[test]
fn install_into_empty_mcp_servers_and_compact_files() {
    let c = &CLIENTS[3];
    for (original, compact) in [
        ("{}", true),
        ("{\"mcpServers\":{}}", true),
        ("{\n  \"mcpServers\": {}\n}\n", false),
    ] {
        let h = home();
        let p = write_file(h.path(), c, original);
        ok(&run("install", h.path(), c.name, &[]));
        assert!(entry(&p, c).is_some(), "{original}");
        let after = fs::read_to_string(&p).unwrap();
        assert_eq!(
            after.contains('\n'),
            original.contains('\n') || !compact,
            "{after}"
        );
        ok(&run("uninstall", h.path(), c.name, &[]));
        assert!(entry(&p, c).is_none());
    }
}

#[test]
fn invalid_file_is_refused_untouched() {
    for c in &CLIENTS {
        let h = home();
        let p = write_file(h.path(), c, "{ this is not valid [");
        let o = run("install", h.path(), c.name, &[]);
        assert!(!o.status.success(), "{}", c.name);
        assert_eq!(fs::read_to_string(&p).unwrap(), "{ this is not valid [");
    }
}

#[test]
fn backup_written_once() {
    for c in &CLIENTS {
        let h = home();
        let original = with_other(c);
        let p = write_file(h.path(), c, &original);
        let bak = PathBuf::from(format!("{}.onepass-bak", p.display()));
        ok(&run("install", h.path(), c.name, &[]));
        assert_eq!(fs::read_to_string(&bak).unwrap(), original, "{}", c.name);
        // A second, different install keeps the first backup.
        ok(&run(
            "install",
            h.path(),
            c.name,
            &["--force", "--socket", "/tmp/other.sock"],
        ));
        assert_eq!(fs::read_to_string(&bak).unwrap(), original, "{}", c.name);
        assert_eq!(entry(&p, c).unwrap().1[1], "/tmp/other.sock");
    }
}

#[test]
fn no_backup_for_a_new_file() {
    let c = &CLIENTS[0];
    let h = home();
    ok(&run("install", h.path(), c.name, &[]));
    assert!(
        !file_of(h.path(), c)
            .with_extension("json.onepass-bak")
            .exists()
    );
    let names: Vec<_> = fs::read_dir(h.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
}

#[test]
fn existing_other_path_needs_force() {
    for c in &CLIENTS {
        let h = home();
        let other = match c.format {
            Format::Json => "{\"mcpServers\":{\"onepass\":{\"command\":\"/elsewhere/onepass-mcp\",\"args\":[\"--socket\",\"/s\"]}}}".to_owned(),
            Format::Toml => "[mcp_servers.onepass]\ncommand = \"/elsewhere/onepass-mcp\"\nargs = [\"--socket\", \"/s\"]\n".to_owned(),
        };
        let p = write_file(h.path(), c, &other);
        let o = run("install", h.path(), c.name, &[]);
        assert!(!o.status.success(), "{}", c.name);
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("--force"),
            "{}",
            c.name
        );
        assert_eq!(fs::read_to_string(&p).unwrap(), other, "{}", c.name);
        ok(&run("install", h.path(), c.name, &["--force"]));
        assert_eq!(entry(&p, c).unwrap().0, relay_path(), "{}", c.name);
        // Same entry again: nothing to do, no --force needed.
        let before = fs::read_to_string(&p).unwrap();
        ok(&run("install", h.path(), c.name, &[]));
        assert_eq!(fs::read_to_string(&p).unwrap(), before, "{}", c.name);
    }
}

#[test]
// Unix only: compares the default socket, a path in the Mac app's
// container written with forward slashes.
#[cfg(unix)]
fn dry_run_writes_nothing_and_prints_diff() {
    for c in &CLIENTS {
        let h = home();
        let o = run("install", h.path(), c.name, &["--dry-run", "--with-docs"]);
        ok(&o);
        let out = String::from_utf8_lossy(&o.stdout);
        assert!(
            out.lines()
                .any(|l| l.starts_with('+') && l.contains("onepass")),
            "{}: {out}",
            c.name
        );
        assert!(out.contains(&relay_path()), "{}", c.name);
        assert_eq!(
            fs::read_dir(h.path()).unwrap().count(),
            0,
            "{} created something",
            c.name
        );

        let original = with_other(c);
        let p = write_file(h.path(), c, &original);
        ok(&run("install", h.path(), c.name, &["--dry-run"]));
        assert_eq!(fs::read_to_string(&p).unwrap(), original);
        assert!(!PathBuf::from(format!("{}.onepass-bak", p.display())).exists());
    }
}

#[test]
fn uninstall_removes_only_onepass() {
    for c in &CLIENTS {
        let h = home();
        let original = with_other(c);
        let p = write_file(h.path(), c, &original);
        ok(&run("install", h.path(), c.name, &[]));
        ok(&run("uninstall", h.path(), c.name, &[]));
        assert!(entry(&p, c).is_none(), "{}", c.name);
        assert!(has_other(&p, c), "{}", c.name);
        assert_eq!(fs::read_to_string(&p).unwrap(), original, "{}", c.name);
        // Uninstalling when nothing is there, or no file, is fine.
        ok(&run("uninstall", h.path(), c.name, &[]));
        let h2 = home();
        ok(&run("uninstall", h2.path(), c.name, &[]));
        assert_eq!(fs::read_dir(h2.path()).unwrap().count(), 0);
    }
}

#[test]
fn with_docs_writes_skill() {
    for c in &CLIENTS {
        let h = home();
        let o = run("install", h.path(), c.name, &["--with-docs"]);
        ok(&o);
        let skill = h.path().join(".claude/skills/onepass/SKILL.md");
        if c.name == "claude-code" {
            let t = fs::read_to_string(&skill).unwrap();
            for needle in [
                "onepass://",
                "run_with_secrets",
                "fill_template",
                "reveal_secret",
                "untrusted_vault_data",
                "confirmation code",
                "OnePass is locked on this Mac. Approve on your iPhone or unlock the app.",
            ] {
                assert!(t.contains(needle), "SKILL.md lacks {needle}");
            }
            assert!(!t.contains('\u{2014}'));
        } else {
            assert!(!skill.exists(), "{}", c.name);
            let out = String::from_utf8_lossy(&o.stdout);
            assert!(
                out.contains("onepass://") && out.contains("untrusted_vault_data"),
                "{}",
                c.name
            );
        }
    }
}

#[test]
#[cfg(unix)]
fn write_is_atomic() {
    for c in &CLIENTS {
        let h = home();
        let p = write_file(h.path(), c, &with_other(c));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        let ino = fs::metadata(&p).unwrap().ino();
        ok(&run("install", h.path(), c.name, &[]));
        let m = fs::metadata(&p).unwrap();
        // A temporary file replaced the original by renaming.
        assert_ne!(m.ino(), ino, "{}", c.name);
        assert_eq!(m.permissions().mode() & 0o777, 0o640, "{}", c.name);
        let names: Vec<String> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "temporary file left behind: {names:?}");
        assert!(names.iter().any(|n| n.ends_with(".onepass-bak")));
    }
}

#[test]
fn unknown_client_and_missing_flags_are_usage_errors() {
    let h = home();
    let o = run("install", h.path(), "vim", &[]);
    assert_eq!(o.status.code(), Some(64));
    let o = Command::new(BIN).arg("install").output().unwrap();
    assert_eq!(o.status.code(), Some(64));
}

#[test]
fn toml_comment_above_onepass_survives_force_and_uninstall() {
    let c = &CLIENTS[2];
    let h = home();
    let original = "[mcp_servers.a]\ncommand = \"a\"\n\n# OnePass, set up by hand\n# keep me\n[mcp_servers.onepass] # header note\ncommand = \"/elsewhere\"\nargs = [\"--socket\", \"/s\"]\n\n[mcp_servers.b]\ncommand = \"b\"\n";
    let p = write_file(h.path(), c, original);
    ok(&run("install", h.path(), c.name, &["--force"]));
    let after = fs::read_to_string(&p).unwrap();
    assert!(
        after.contains(
            "# OnePass, set up by hand\n# keep me\n[mcp_servers.onepass] # header note\n"
        ),
        "{after}"
    );
    // Same place: still between a and b.
    assert!(after.find("mcp_servers.onepass").unwrap() < after.find("mcp_servers.b").unwrap());
    assert_eq!(entry(&p, c).unwrap().0, relay_path());
    ok(&run("uninstall", h.path(), c.name, &[]));
    let after = fs::read_to_string(&p).unwrap();
    assert!(
        after.contains("# OnePass, set up by hand\n# keep me\n"),
        "{after}"
    );
    assert!(
        after.contains("# keep me\n\n[mcp_servers.b]")
            || after.contains("# keep me\n[mcp_servers.b]"),
        "{after}"
    );
    assert!(entry(&p, c).is_none());

    // The table is the last one: the comment stays at the end of the file.
    let last = "[mcp_servers.a]\ncommand = \"a\"\n\n# only mine\n[mcp_servers.onepass]\ncommand = \"/elsewhere\"\nargs = [\"--socket\", \"/s\"]\n";
    let p = write_file(h.path(), c, last);
    ok(&run("uninstall", h.path(), c.name, &[]));
    let after = fs::read_to_string(&p).unwrap();
    assert!(after.contains("# only mine"), "{after}");
    assert!(entry(&p, c).is_none());
}

#[test]
fn duplicate_mcp_servers_is_refused() {
    for c in CLIENTS.iter().filter(|c| c.format == Format::Json) {
        let h = home();
        let dup = "{\"mcpServers\":{\"a\":{}},\"mcpServers\":{\"b\":{}}}";
        let p = write_file(h.path(), c, dup);
        for sub in ["install", "uninstall"] {
            let o = run(sub, h.path(), c.name, &["--force"]);
            assert!(!o.status.success(), "{} {sub}", c.name);
            assert!(String::from_utf8_lossy(&o.stderr).contains("more than once"));
            assert_eq!(fs::read_to_string(&p).unwrap(), dup);
        }
    }
}

#[test]
fn json_style_one_line_crlf_and_only_server() {
    let c = &CLIENTS[3];
    // One line with a trailing newline stays one line.
    let h = home();
    let one = "{\"theme\":\"dark\",\"mcpServers\":{\"other\":{\"command\":\"o\"}}}\n";
    let p = write_file(h.path(), c, one);
    ok(&run("install", h.path(), c.name, &[]));
    let after = fs::read_to_string(&p).unwrap();
    assert_eq!(after.trim_end().lines().count(), 1, "{after}");
    assert!(after.ends_with("}\n") && entry(&p, c).is_some());
    ok(&run("uninstall", h.path(), c.name, &[]));
    assert_eq!(fs::read_to_string(&p).unwrap(), one);

    // CRLF files get CRLF, and come back exactly.
    let h = home();
    let crlf = "{\r\n  \"mcpServers\": {\r\n    \"other\": {\r\n      \"command\": \"o\"\r\n    }\r\n  }\r\n}\r\n";
    let p = write_file(h.path(), c, crlf);
    ok(&run("install", h.path(), c.name, &[]));
    let after = fs::read_to_string(&p).unwrap();
    assert_eq!(
        after.matches('\n').count(),
        after.matches("\r\n").count(),
        "{after:?}"
    );
    assert!(entry(&p, c).is_some());
    ok(&run("uninstall", h.path(), c.name, &[]));
    assert_eq!(fs::read_to_string(&p).unwrap(), crlf);

    // Removing the only server leaves {} and nothing else behind.
    let h = home();
    let p = write_file(h.path(), c, "{\n  \"mcpServers\": {}\n}\n");
    ok(&run("install", h.path(), c.name, &[]));
    ok(&run("uninstall", h.path(), c.name, &[]));
    assert_eq!(
        fs::read_to_string(&p).unwrap(),
        "{\n  \"mcpServers\": {}\n}\n"
    );
}

#[test]
fn claude_code_entry_keys_are_ordered_and_message_says_quit() {
    let c = &CLIENTS[0];
    let h = home();
    let o = run("install", h.path(), c.name, &[]);
    ok(&o);
    let text = fs::read_to_string(file_of(h.path(), c)).unwrap();
    let at = |k: &str| text.find(k).unwrap_or_else(|| panic!("{k} in {text}"));
    assert!(
        at("\"type\"") < at("\"command\"") && at("\"command\"") < at("\"args\""),
        "{text}"
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("Quit Claude Code first"));
}

#[test]
fn nested_or_string_mcp_servers_is_not_a_duplicate() {
    for c in CLIENTS.iter().filter(|c| c.format == Format::Json) {
        let h = home();
        // Claude Code keeps per-project servers under `projects`, and any
        // string may say "mcpServers": only the top-level key counts.
        let text = "{\n  \"projects\": {\"/w\": {\"mcpServers\": {\"p\": {\"command\": \"p\"}}}},\n  \"note\": \"mcpServers\",\n  \"list\": [\"mcpServers\", {\"mcpServers\": 1}],\n  \"mcpServers\": {\"other\": {\"command\": \"o\"}}\n}\n";
        let p = write_file(h.path(), c, text);
        ok(&run("install", h.path(), c.name, &[]));
        assert_eq!(entry(&p, c).unwrap().0, relay_path(), "{}", c.name);
        let v: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["other"]["command"], "o");
        assert!(v["projects"]["/w"]["mcpServers"].get("onepass").is_none());
        assert_eq!(v["note"], "mcpServers");
        ok(&run("uninstall", h.path(), c.name, &[]));
        assert_eq!(fs::read_to_string(&p).unwrap(), text, "{}", c.name);
    }
}

#[test]
fn socket_paths_are_escaped() {
    let socket = "/tmp/a \"b\"\\c é\t#[x].sock";
    for c in &CLIENTS {
        let h = home();
        let p = write_file(h.path(), c, &with_other(c));
        ok(&run("install", h.path(), c.name, &["--socket", socket]));
        let (_, args) = entry(&p, c).unwrap();
        assert_eq!(
            args,
            vec!["--socket".to_owned(), socket.to_owned()],
            "{}",
            c.name
        );
        assert!(has_other(&p, c), "{}", c.name);
        // The same entry again is recognized, and removed cleanly.
        let o = run("install", h.path(), c.name, &["--socket", socket]);
        ok(&o);
        assert!(
            String::from_utf8_lossy(&o.stdout).contains("already"),
            "{}",
            c.name
        );
        ok(&run("uninstall", h.path(), c.name, &[]));
        assert!(entry(&p, c).is_none(), "{}", c.name);
    }
}
