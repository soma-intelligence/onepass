//! `onepass-mcp install|uninstall --client <client>`: writes (or removes)
//! the OnePass MCP server entry in a client's own configuration file
//! (agent-ready spec 2026-10-28, section 8).
//!
//! Per-client table, checked against each client's documentation on
//! 2026-10-29 (it matches the table of the spec):
//!
//! | client         | file (under the home)                                    | entry                    |
//! |----------------|----------------------------------------------------------|--------------------------|
//! | claude-code    | `.claude.json` (user scope, top-level `mcpServers`)      | `mcpServers.onepass`     |
//! | claude-desktop | `Library/Application Support/Claude/claude_desktop_config.json` | `mcpServers.onepass` |
//! | codex          | `.codex/config.toml`                                     | `[mcp_servers.onepass]`  |
//! | cursor         | `.cursor/mcp.json` (global)                              | `mcpServers.onepass`     |
//!
//! Sources:
//! - Claude Code: <https://code.claude.com/docs/en/mcp> (user scope is stored
//!   in `~/.claude.json`; an entry with no `type` is stdio; `command`, `args`,
//!   `env`). We write `"type": "stdio"` explicitly.
//! - Claude desktop: <https://modelcontextprotocol.io/quickstart/user>
//!   (`~/Library/Application Support/Claude/claude_desktop_config.json`,
//!   `mcpServers.<name>.command` and `.args`).
//! - Codex: <https://developers.openai.com/codex/mcp> (`~/.codex/config.toml`,
//!   `[mcp_servers.<name>]` with `command` and `args`).
//! - Cursor: <https://cursor.com/docs/context/mcp> (`~/.cursor/mcp.json`,
//!   `mcpServers` with `command` and `args`).
//!
//! Guarantees. TOML is edited with `toml_edit`: comments, order and
//! formatting outside the `onepass` table are kept. JSON is edited as text:
//! a small scanner finds the byte span of the `onepass` member and only that
//! span (plus its separating comma) is inserted, replaced or removed, so
//! every other byte of the file is unchanged, even in a multi-megabyte
//! `~/.claude.json`. The file must parse first, or nothing is written.
//! Writes go to a temporary file in the same directory that replaces the
//! original by renaming, keeping its permissions; a symlinked file is
//! written through. The first modification of an existing file leaves
//! `<file>.onepass-bak` beside it; it is never overwritten.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const SKILL: &str = include_str!("../assets/SKILL.md");
const AGENTS_SNIPPET: &str = include_str!("../assets/AGENTS-snippet.md");

/// Bundle identifier of the Mac app; its sandbox container holds the socket.
const APP_ID: &str = "me.somalabs.onepass";
const SERVER: &str = "onepass";

pub const USAGE: &str = "usage: onepass-mcp install|uninstall --client <claude-code|claude-desktop|codex|cursor> [--dry-run] [--force] [--with-docs] [--home <dir>] [--socket <path>]";

#[derive(Debug)]
pub enum Error {
    Usage(String),
    Failed(String),
}

impl Error {
    fn failed(m: impl Into<String>) -> Self {
        Error::Failed(m.into())
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Failed(e.to_string())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Client {
    ClaudeCode,
    ClaudeDesktop,
    Codex,
    Cursor,
}

impl Client {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "claude-code" => Client::ClaudeCode,
            "claude-desktop" => Client::ClaudeDesktop,
            "codex" => Client::Codex,
            "cursor" => Client::Cursor,
            _ => return None,
        })
    }

    fn config_path(self, home: &Path) -> PathBuf {
        home.join(match self {
            Client::ClaudeCode => ".claude.json",
            Client::ClaudeDesktop => {
                "Library/Application Support/Claude/claude_desktop_config.json"
            }
            Client::Codex => ".codex/config.toml",
            Client::Cursor => ".cursor/mcp.json",
        })
    }

    fn display_name(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::ClaudeDesktop => "Claude desktop",
            Client::Codex => "Codex",
            Client::Cursor => "Cursor",
        }
    }

    fn is_toml(self) -> bool {
        self == Client::Codex
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Uninstall,
}

struct Options {
    client: Client,
    dry_run: bool,
    force: bool,
    with_docs: bool,
    home: PathBuf,
    socket: Option<PathBuf>,
}

fn parse_args(args: &[OsString]) -> Result<Options, Error> {
    let usage = |m: &str| Error::Usage(format!("{m}\n{USAGE}"));
    let (mut client, mut home, mut socket) = (None, None, None);
    let (mut dry_run, mut force, mut with_docs) = (false, false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let a = a.to_str().ok_or_else(|| usage("argument is not UTF-8"))?;
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) => (f, Some(v.to_owned())),
            None => (a, None),
        };
        let mut value = |name: &str| -> Result<OsString, Error> {
            match inline.clone() {
                Some(v) => Ok(OsString::from(v)),
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| usage(&format!("{name} needs a value"))),
            }
        };
        match flag {
            "--client" => client = Some(value("--client")?),
            "--home" => home = Some(PathBuf::from(value("--home")?)),
            "--socket" => socket = Some(PathBuf::from(value("--socket")?)),
            "--dry-run" => dry_run = true,
            "--force" => force = true,
            "--with-docs" => with_docs = true,
            _ => return Err(usage(&format!("unknown argument {a}"))),
        }
    }
    let client = client.ok_or_else(|| usage("--client is required"))?;
    let client = client
        .to_str()
        .and_then(Client::parse)
        .ok_or_else(|| usage("unknown client"))?;
    let home = match home {
        Some(h) => h,
        None => std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| Error::failed("HOME is not set, pass --home"))?,
    };
    Ok(Options {
        client,
        dry_run,
        force,
        with_docs,
        home,
        socket,
    })
}

/// The socket of the app: `<container>/.onepass/mcp.sock`, the container
/// being the sandbox `Data` folder of the app (`NSHomeDirectory()` there).
fn default_socket(home: &Path) -> PathBuf {
    home.join("Library/Containers")
        .join(APP_ID)
        .join("Data/.onepass/mcp.sock")
}

/// Runs `install` or `uninstall`; `args` are the arguments after it.
pub fn run(action: Action, args: &[OsString], out: &mut dyn Write) -> Result<(), Error> {
    let o = parse_args(args)?;
    let exe = fs::canonicalize(std::env::current_exe()?)?;
    let exe = exe
        .to_str()
        .ok_or_else(|| Error::failed("the path of the relay is not UTF-8"))?
        .to_owned();
    let socket = o.socket.clone().unwrap_or_else(|| default_socket(&o.home));
    let socket = socket
        .to_str()
        .ok_or_else(|| Error::failed("the socket path is not UTF-8"))?
        .to_owned();
    let entry = Entry {
        command: exe,
        socket,
        typed: o.client == Client::ClaudeCode,
    };

    let path = o.client.config_path(&o.home);
    let existing = read_existing(&path)?;
    let edit = if o.client.is_toml() {
        edit_toml(existing.as_deref(), action, &entry, o.force)?
    } else {
        edit_json(existing.as_deref(), action, &entry, o.force)?
    };
    match edit {
        Edit::Unchanged(msg) => writeln!(out, "{msg} ({})", path.display())?,
        Edit::Changed(new) => {
            if o.dry_run {
                writeln!(out, "--- {}\n+++ {}", path.display(), path.display())?;
                out.write_all(diff(existing.as_deref().unwrap_or(""), &new).as_bytes())?;
            } else {
                if existing.is_some() {
                    backup_once(&path)?;
                }
                write_atomic(&path, new.as_bytes())?;
                let verb = if action == Action::Install {
                    "installed in"
                } else {
                    "removed from"
                };
                writeln!(out, "OnePass {verb} {}", path.display())?;
                writeln!(
                    out,
                    "Quit {} first if it is running, then start it again: it can rewrite its configuration file and undo this change.",
                    o.client.display_name()
                )?;
            }
        }
    }

    if o.with_docs && action == Action::Install {
        if o.client == Client::ClaudeCode {
            let skill = o.home.join(".claude/skills/onepass/SKILL.md");
            if o.dry_run {
                writeln!(out, "would write {}", skill.display())?;
            } else {
                write_atomic(&skill, SKILL.as_bytes())?;
                writeln!(out, "wrote {}", skill.display())?;
            }
        } else {
            writeln!(
                out,
                "\nAdd this to the AGENTS.md of your projects:\n\n{AGENTS_SNIPPET}"
            )?;
        }
    }
    Ok(())
}

struct Entry {
    command: String,
    socket: String,
    /// Claude Code gets an explicit `"type": "stdio"`.
    typed: bool,
}

enum Edit {
    Unchanged(&'static str),
    Changed(String),
}

fn read_existing(path: &Path) -> Result<Option<String>, Error> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::failed(format!(
            "cannot read {}: {e}",
            path.display()
        ))),
    }
}

fn needs_force(what: &str) -> Error {
    Error::failed(format!(
        "{what} already has an onepass entry that points elsewhere, nothing changed. Run again with --force to replace it"
    ))
}

// ---- TOML ------------------------------------------------------------

fn edit_toml(src: Option<&str>, action: Action, e: &Entry, force: bool) -> Result<Edit, Error> {
    use toml_edit::{Array, DocumentMut, Item, Table, value};
    let mut doc: DocumentMut = match src {
        Some(s) => s.parse().map_err(|err| {
            Error::failed(format!(
                "the file is not valid TOML, nothing changed: {err}"
            ))
        })?,
        None => DocumentMut::new(),
    };
    let existing = doc
        .get("mcp_servers")
        .and_then(Item::as_table_like)
        .and_then(|t| t.get(SERVER))
        .cloned();
    let same = existing.as_ref().is_some_and(|it| {
        it.get("command").and_then(Item::as_str) == Some(&e.command)
            && it.get("args").and_then(Item::as_array).is_some_and(|a| {
                let v: Vec<_> = a.iter().filter_map(|x| x.as_str()).collect();
                v == ["--socket", e.socket.as_str()]
            })
    });
    match action {
        Action::Uninstall => {
            if existing.is_none() {
                return Ok(Edit::Unchanged("OnePass is not in this file"));
            }
            // A comment block above the table goes to whatever follows it.
            let old = existing.as_ref().and_then(Item::as_table);
            let comment = old
                .and_then(|t| t.decor().prefix().and_then(|p| p.as_str()))
                .filter(|p| p.contains('#'))
                .map(str::to_owned);
            let old_pos = old.and_then(Table::position);
            let servers = doc
                .get_mut("mcp_servers")
                .and_then(Item::as_table_like_mut)
                .ok_or_else(|| Error::failed("mcp_servers is not a table"))?;
            servers.remove(SERVER);
            if let Some(comment) = comment {
                let next = old_pos.and_then(|p| next_position(doc.as_table(), p));
                let moved = next.is_some_and(|n| prepend_to_table(doc.as_table_mut(), n, &comment));
                if !moved {
                    let trailing = doc.trailing().as_str().unwrap_or("").to_owned();
                    doc.set_trailing(format!("{comment}{trailing}"));
                }
            }
        }
        Action::Install => {
            if same {
                return Ok(Edit::Unchanged("OnePass is already installed"));
            }
            if existing.is_some() && !force {
                return Err(needs_force("this file"));
            }
            if doc.get("mcp_servers").is_none() {
                let mut t = Table::new();
                t.set_implicit(true);
                doc["mcp_servers"] = Item::Table(t);
            }
            let servers = doc["mcp_servers"]
                .as_table_like_mut()
                .ok_or_else(|| Error::failed("mcp_servers is not a table"))?;
            let mut t = Table::new();
            t["command"] = value(e.command.as_str());
            let mut args = Array::new();
            args.push("--socket");
            args.push(e.socket.as_str());
            t["args"] = value(args);
            // Replacing keeps the old table's comments, header note and place.
            if let Some(old) = existing.as_ref().and_then(Item::as_table) {
                *t.decor_mut() = old.decor().clone();
                t.set_position(old.position());
            }
            servers.insert(SERVER, Item::Table(t));
        }
    }
    let new = doc.to_string();
    new.parse::<DocumentMut>().map_err(|err| {
        Error::failed(format!(
            "internal error, the result is not valid TOML: {err}"
        ))
    })?;
    Ok(Edit::Changed(new))
}

/// The smallest table position greater than `after` under `t`.
fn next_position(t: &toml_edit::Table, after: isize) -> Option<isize> {
    let mut best = t.position().filter(|p| *p > after);
    for (_, item) in t.iter() {
        let found = match item {
            toml_edit::Item::Table(sub) => next_position(sub, after),
            toml_edit::Item::ArrayOfTables(a) => {
                a.iter().filter_map(|sub| next_position(sub, after)).min()
            }
            _ => None,
        };
        best = match (best, found) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    best
}

/// Puts `text` before the header of the table at `position`.
fn prepend_to_table(t: &mut toml_edit::Table, position: isize, text: &str) -> bool {
    if t.position() == Some(position) {
        let old = t
            .decor()
            .prefix()
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_owned();
        t.decor_mut().set_prefix(format!("{text}{old}"));
        return true;
    }
    for (_, item) in t.iter_mut() {
        let done = match item {
            toml_edit::Item::Table(sub) => prepend_to_table(sub, position, text),
            toml_edit::Item::ArrayOfTables(a) => a
                .iter_mut()
                .any(|sub| prepend_to_table(sub, position, text)),
            _ => false,
        };
        if done {
            return true;
        }
    }
    false
}

// ---- JSON ------------------------------------------------------------

/// One member of a JSON object, as byte offsets into the text.
struct Member {
    key: String,
    key_start: usize,
    val_start: usize,
    val_end: usize,
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

/// End (exclusive) of the string that starts at `i` (a quote).
fn string_end(s: &[u8], mut i: usize) -> Result<usize, Error> {
    i += 1;
    while i < s.len() {
        match s[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i + 1),
            _ => i += 1,
        }
    }
    Err(Error::failed("unterminated JSON string"))
}

/// End (exclusive) of the JSON value that starts at `i`.
fn value_end(s: &[u8], i: usize) -> Result<usize, Error> {
    match s.get(i) {
        Some(b'"') => string_end(s, i),
        Some(b'{' | b'[') => {
            let mut depth = 0usize;
            let mut j = i;
            while j < s.len() {
                match s[j] {
                    b'"' => {
                        j = string_end(s, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Ok(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            Err(Error::failed("unterminated JSON value"))
        }
        Some(_) => {
            let mut j = i;
            while j < s.len() && !matches!(s[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            {
                j += 1;
            }
            Ok(j)
        }
        None => Err(Error::failed("unexpected end of JSON")),
    }
}

/// The members of the object whose `{` is at `open`, and the offset of its `}`.
fn members(s: &[u8], open: usize) -> Result<(Vec<Member>, usize), Error> {
    debug_assert_eq!(s[open], b'{');
    let mut out = Vec::new();
    let mut i = skip_ws(s, open + 1);
    loop {
        match s.get(i) {
            Some(b'}') => return Ok((out, i)),
            Some(b'"') => {}
            _ => return Err(Error::failed("malformed JSON object")),
        }
        let key_end = string_end(s, i)?;
        let key: String = serde_json::from_slice(&s[i..key_end])
            .map_err(|e| Error::failed(format!("malformed JSON key: {e}")))?;
        let colon = skip_ws(s, key_end);
        if s.get(colon) != Some(&b':') {
            return Err(Error::failed("malformed JSON object"));
        }
        let val_start = skip_ws(s, colon + 1);
        let val_end = value_end(s, val_start)?;
        out.push(Member {
            key,
            key_start: i,
            val_start,
            val_end,
        });
        i = skip_ws(s, val_end);
        if s.get(i) == Some(&b',') {
            i = skip_ws(s, i + 1);
        }
    }
}

fn json_str(s: &str) -> String {
    serde_json::Value::from(s).to_string()
}

/// The entry as text, keys in the order type, command, args, for a member
/// whose line is indented by `indent` (pretty, 2-space steps) or compact.
fn entry_text(e: &Entry, pretty: bool, nl: &str, indent: &str) -> String {
    let (command, socket) = (json_str(&e.command), json_str(&e.socket));
    if !pretty {
        let ty = if e.typed { "\"type\":\"stdio\"," } else { "" };
        return format!("{{{ty}\"command\":{command},\"args\":[\"--socket\",{socket}]}}");
    }
    let (i1, i2) = (format!("{indent}  "), format!("{indent}    "));
    let ty = if e.typed {
        format!("{nl}{i1}\"type\": \"stdio\",")
    } else {
        String::new()
    };
    format!(
        "{{{ty}{nl}{i1}\"command\": {command},{nl}{i1}\"args\": [{nl}{i2}\"--socket\",{nl}{i2}{socket}{nl}{i1}]{nl}{indent}}}"
    )
}

/// `{ "onepass": <entry> }`, the value of a new `mcpServers` member.
fn servers_text(e: &Entry, pretty: bool, nl: &str, indent: &str) -> String {
    if !pretty {
        return format!("{{\"{SERVER}\":{}}}", entry_text(e, false, nl, ""));
    }
    let inner = format!("{indent}  ");
    format!(
        "{{{nl}{inner}\"{SERVER}\": {}{nl}{indent}}}",
        entry_text(e, true, nl, &inner)
    )
}

/// Indentation of the line that holds offset `at`.
fn line_indent(text: &str, at: usize) -> String {
    let start = text[..at].rfind('\n').map_or(0, |n| n + 1);
    text[start..]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

/// How the file is laid out, so the new text matches it.
struct Style {
    pretty: bool,
    nl: &'static str,
}

impl Style {
    fn of(text: &str) -> Self {
        Style {
            pretty: text.trim_end().contains('\n'),
            nl: if text.contains("\r\n") { "\r\n" } else { "\n" },
        }
    }
}

/// Inserts or replaces `key` in the object at `open`; `value(indent)` is the
/// text of the value for a member line indented by `indent`.
fn set_member(
    text: &str,
    open: usize,
    key: &str,
    st: &Style,
    value: &dyn Fn(&str) -> String,
) -> Result<String, Error> {
    let s = text.as_bytes();
    let (ms, close) = members(s, open)?;
    if let Some(m) = ms.iter().find(|m| m.key == key) {
        let indent = line_indent(text, m.key_start);
        return Ok(format!(
            "{}{}{}",
            &text[..m.val_start],
            value(&indent),
            &text[m.val_end..]
        ));
    }
    let key_json = json_str(key);
    let colon = if st.pretty { ": " } else { ":" };
    if let Some(last) = ms.last() {
        let lead = &text[open + 1..ms[0].key_start];
        let indent = lead
            .rsplit('\n')
            .next()
            .filter(|_| lead.contains('\n'))
            .unwrap_or("");
        let member = format!("{key_json}{colon}{}", value(indent));
        Ok(format!(
            "{},{lead}{member}{}",
            &text[..last.val_end],
            &text[last.val_end..]
        ))
    } else if st.pretty {
        let base = line_indent(text, open);
        let inner = format!("{base}  ");
        let nl = st.nl;
        let member = format!("{key_json}{colon}{}", value(&inner));
        Ok(format!(
            "{}{nl}{inner}{member}{nl}{base}{}",
            &text[..open + 1],
            &text[close..]
        ))
    } else {
        let member = format!("{key_json}{colon}{}", value(""));
        Ok(format!("{}{member}{}", &text[..open + 1], &text[close..]))
    }
}

/// Removes member `idx` of `ms` (with its comma). The only member leaves `{}`.
fn remove_member(text: &str, ms: &[Member], idx: usize, open: usize, close: usize) -> String {
    let m = &ms[idx];
    let (from, to) = if ms.len() == 1 {
        (open + 1, close)
    } else if idx + 1 < ms.len() {
        (m.key_start, ms[idx + 1].key_start)
    } else {
        (ms[idx - 1].val_end, m.val_end)
    };
    format!("{}{}", &text[..from], &text[to..])
}

fn edit_json(src: Option<&str>, action: Action, e: &Entry, force: bool) -> Result<Edit, Error> {
    let mut same_entry = serde_json::json!({
        "command": e.command,
        "args": ["--socket", e.socket],
    });
    if e.typed {
        same_entry["type"] = "stdio".into();
    }

    let text = match src {
        Some(t) if !t.trim().is_empty() => t,
        _ => {
            if action == Action::Uninstall {
                return Ok(Edit::Unchanged("OnePass is not in this file"));
            }
            return Ok(Edit::Changed(format!(
                "{{\n  \"mcpServers\": {}\n}}\n",
                servers_text(e, true, "\n", "  ")
            )));
        }
    };
    serde_json::from_str::<serde::de::IgnoredAny>(text).map_err(|err| {
        Error::failed(format!(
            "the file is not valid JSON, nothing changed: {err}"
        ))
    })?;
    let s = text.as_bytes();
    let root = skip_ws(s, 0);
    if s[root] != b'{' {
        return Err(Error::failed(
            "the file is not a JSON object, nothing changed",
        ));
    }
    let st = Style::of(text);
    let (root_ms, _) = members(s, root)?;
    let mut servers = root_ms.iter().filter(|m| m.key == "mcpServers");
    let servers = servers
        .next()
        .map(|first| (first, servers.next().is_some()));
    if servers.is_some_and(|(_, dup)| dup) {
        return Err(Error::failed(
            "mcpServers appears more than once in the file (clients use the last one), nothing changed",
        ));
    }
    let servers = servers.map(|(m, _)| m);
    if let Some(sv) = servers
        && s[sv.val_start] != b'{'
    {
        return Err(Error::failed(
            "mcpServers is not an object, nothing changed",
        ));
    }
    // (open, close, members, index of onepass)
    let found = match servers {
        Some(sv) => {
            let (ms, close) = members(s, sv.val_start)?;
            let mut hits = ms.iter().enumerate().filter(|(_, m)| m.key == SERVER);
            let idx = hits.next().map(|(i, _)| i);
            if hits.next().is_some() {
                return Err(Error::failed(
                    "onepass appears more than once in mcpServers, nothing changed",
                ));
            }
            Some((sv.val_start, close, ms, idx))
        }
        None => None,
    };
    let existing: Option<serde_json::Value> = match &found {
        Some((_, _, ms, Some(i))) => {
            serde_json::from_str(&text[ms[*i].val_start..ms[*i].val_end]).ok()
        }
        _ => None,
    };
    let present = matches!(&found, Some((_, _, _, Some(_))));
    let new = match action {
        Action::Uninstall => {
            let Some((open, close, ms, Some(i))) = &found else {
                return Ok(Edit::Unchanged("OnePass is not in this file"));
            };
            remove_member(text, ms, *i, *open, *close)
        }
        Action::Install => {
            let same = existing.as_ref().is_some_and(|v| {
                v.get("command") == same_entry.get("command")
                    && v.get("args") == same_entry.get("args")
            });
            if same {
                return Ok(Edit::Unchanged("OnePass is already installed"));
            }
            if present && !force {
                return Err(needs_force("this file"));
            }
            match &found {
                Some((open, _, _, _)) => set_member(text, *open, SERVER, &st, &|ind| {
                    entry_text(e, st.pretty, st.nl, ind)
                })?,
                None => set_member(text, root, "mcpServers", &st, &|ind| {
                    servers_text(e, st.pretty, st.nl, ind)
                })?,
            }
        }
    };
    serde_json::from_str::<serde::de::IgnoredAny>(&new).map_err(|err| {
        Error::failed(format!(
            "internal error, the result is not valid JSON: {err}"
        ))
    })?;
    Ok(Edit::Changed(new))
}

// ---- files -----------------------------------------------------------

/// A line diff of one contiguous change: the lines that differ, with `-`
/// and `+`, a few lines of context around.
fn diff(old: &str, new: &str) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    let pre = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (ca, cb) = (a.len() - suf, b.len() - suf);
    let mut out = String::new();
    let ctx_from = pre.saturating_sub(2);
    for l in &a[ctx_from..pre] {
        let _ = writeln!(out, " {l}");
    }
    for l in &a[pre..ca] {
        let _ = writeln!(out, "-{l}");
    }
    for l in &b[pre..cb] {
        let _ = writeln!(out, "+{l}");
    }
    for l in a[ca..].iter().take(2) {
        let _ = writeln!(out, " {l}");
    }
    out
}

/// Copies `path` to `<path>.onepass-bak` unless that already exists.
fn backup_once(path: &Path) -> Result<(), Error> {
    let real = fs::canonicalize(path)?;
    let mut name = real.as_os_str().to_owned();
    name.push(".onepass-bak");
    let bak = PathBuf::from(name);
    if bak.exists() {
        return Ok(());
    }
    fs::copy(&real, &bak)
        .map_err(|e| Error::failed(format!("cannot write the backup {}: {e}", bak.display())))?;
    Ok(())
}

/// Writes `data` to `path` through a temporary file of the same directory,
/// then renames it over `path`. Keeps the permissions of an existing file
/// (0600 for a new one) and writes through a symlink.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), Error> {
    let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = path
        .parent()
        .ok_or_else(|| Error::failed("the file has no directory"))?;
    fs::create_dir_all(dir)?;
    let mode = fs::metadata(&path).map_or(0o600, |m| m.permissions().mode() & 0o7777);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut tmp = dir.join(format!(".{name}.onepass-tmp-{:016x}", random()));
    let result = (|| -> io::Result<()> {
        // A stale temporary file with the same name cannot block the write:
        // the name is random, and a collision picks another one.
        let mut f = None;
        for _ in 0..8 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)
            {
                Ok(file) => {
                    f = Some(file);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    tmp = dir.join(format!(".{name}.onepass-tmp-{:016x}", random()));
                }
                Err(e) => return Err(e),
            }
        }
        let mut f = f.ok_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists))?;
        f.write_all(data)?;
        // The umask may have narrowed the mode at creation.
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(|e| Error::failed(format!("cannot write {}: {e}", path.display())))
}

/// A random 64-bit number (the std hasher is seeded by the OS).
fn random() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}
