//! Code-signing identity of local clients.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::cred::{PeerCred, parent_of, parent_pid};

/// Identifiers of the system launchers skipped when looking for the MCP
/// client (spec 3.2).
pub const LAUNCHERS: [&str; 5] = [
    "com.apple.sh",
    "com.apple.bash",
    "com.apple.zsh",
    "com.apple.dash",
    "com.apple.env",
];

/// Executable paths of the launchers skipped on Linux, where nothing is
/// signed (`/proc/<pid>/exe` names the resolved file).
pub const LINUX_LAUNCHER_PATHS: [&str; 10] = [
    "/bin/sh",
    "/bin/bash",
    "/bin/dash",
    "/bin/zsh",
    "/bin/env",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/dash",
    "/usr/bin/zsh",
    "/usr/bin/env",
];

/// Most launchers skipped above the MCP server (spec 3.2).
pub const MAX_LAUNCHERS: usize = 8;

/// What the system says about the code a process runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeIdentity {
    /// An Apple binary (requirement `anchor apple`).
    Platform { identifier: String },
    /// Signed by a developer (requirement `anchor apple generic`).
    Team { team_id: String, identifier: String },
    /// macOS code signed ad hoc (every locally built binary on Apple
    /// Silicon), or whose developer signature does not hold: pinned by the
    /// kernel's code directory hash of the running image, never by the file.
    /// `hardened` tells whether it runs with the hardened runtime: without
    /// it, the tool may load any library (`DYLD_INSERT_LIBRARIES`) under the
    /// same cdhash. Not part of the client id.
    AdHoc {
        path: PathBuf,
        cdhash: String,
        hardened: bool,
    },
    /// Linux only, where nothing is signed: pinned by the SHA-256 of the
    /// running image (`/proc/<pid>/exe`).
    Unsigned { path: PathBuf, sha256: String },
}

impl CodeIdentity {
    /// Stable client id: `platform:<identifier>`,
    /// `team:<team_id>:<identifier>`, `adhoc:<cdhash hex>` or
    /// `unsigned:<sha256 hex>`.
    pub fn client_id(&self) -> String {
        match self {
            CodeIdentity::Platform { identifier } => format!("platform:{identifier}"),
            CodeIdentity::Team {
                team_id,
                identifier,
            } => format!("team:{team_id}:{identifier}"),
            CodeIdentity::AdHoc { cdhash, .. } => format!("adhoc:{cdhash}"),
            CodeIdentity::Unsigned { sha256, .. } => format!("unsigned:{sha256}"),
        }
    }

    /// Whether the system vouches for the code (platform or team).
    pub fn is_signed(&self) -> bool {
        matches!(
            self,
            CodeIdentity::Platform { .. } | CodeIdentity::Team { .. }
        )
    }

    /// Whether this is a system launcher skipped above the MCP server.
    fn is_launcher(&self) -> bool {
        match self {
            CodeIdentity::Platform { identifier } => LAUNCHERS.contains(&identifier.as_str()),
            // After an upgrade, `/proc/<pid>/exe` of a running shell reads
            // "<path> (deleted)".
            CodeIdentity::Unsigned { path, .. } => path.to_str().is_some_and(|p| {
                LINUX_LAUNCHER_PATHS.contains(&p.strip_suffix(" (deleted)").unwrap_or(p))
            }),
            _ => false,
        }
    }

    /// Whether this is the Linux init system, never a client.
    fn is_init(&self) -> bool {
        matches!(self, CodeIdentity::Unsigned { path, .. }
            if path.file_name().is_some_and(|n| n == "systemd"))
    }
}

/// A local client: its code identity, pid and executable, and for the MCP
/// client the client ids of the ancestors walked to find it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    pub code: CodeIdentity,
    pub pid: i32,
    pub exe: Option<PathBuf>,
    /// Client ids from the direct parent up to and including `code`, for
    /// [`identify_mcp_parent`]; empty otherwise.
    pub chain: Vec<String>,
}

/// Why a client could not be identified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerError {
    /// The process no longer exists.
    Gone,
    /// The system would not tell, or the code is refused: the reason names
    /// the failed step.
    Unreadable(&'static str),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Gone => f.write_str("the client process is gone"),
            PeerError::Unreadable(why) => write!(f, "cannot identify the client: {why}"),
        }
    }
}

impl std::error::Error for PeerError {}

/// Identity of the process `pid`.
pub fn identify_pid(pid: i32) -> Result<ClientIdentity, PeerError> {
    if pid <= 0 {
        return Err(PeerError::Unreadable("invalid pid"));
    }
    #[cfg(target_os = "macos")]
    {
        identify_macos(crate::macos::Guest::Pid(pid), pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        identify_unsigned(pid)
    }
}

/// Identity of a socket peer, by its audit token when the kernel gave one.
pub fn identify_peer(cred: &PeerCred) -> Result<ClientIdentity, PeerError> {
    let pid = cred.pid.ok_or(PeerError::Unreadable("peer pid"))?;
    #[cfg(target_os = "macos")]
    if let Some(token) = cred.audit_token {
        return identify_macos(crate::macos::Guest::AuditToken(token, pid), pid);
    }
    identify_pid(pid)
}

/// Identity of the executable file at `path`, for an explicit pairing: the
/// identity a process running it unmodified has (on macOS the static
/// code's cdhash, equal to the kernel's for an unmodified binary).
pub fn identity_of_file(path: &Path) -> Result<CodeIdentity, PeerError> {
    #[cfg(target_os = "macos")]
    {
        crate::macos::identify_file(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let sha256 = file_sha256(path).map_err(|_| PeerError::Unreadable("executable file"))?;
        Ok(CodeIdentity::Unsigned {
            path: path.to_path_buf(),
            sha256,
        })
    }
}

/// Identity of the MCP client: the first ancestor of this process that is
/// not a launcher (spec 3.2), with the client ids of the ancestors walked.
pub fn identify_mcp_parent() -> Result<ClientIdentity, PeerError> {
    walk_launchers(parent_pid, identify_pid, parent_of)
}

/// From the parent of this process upwards, skips at most
/// [`MAX_LAUNCHERS`] launchers and returns the first other process.
///
/// Each ancestor is identified, then its child is asked again for its
/// parent: if that changed, the pid identified may belong to another
/// process (the ancestor exited and its pid was reused), and the walk fails
/// with `Gone`. It also fails rather than settle for a launcher, pid 1 or
/// the Linux init system (never a client), or an unreadable ancestor.
fn walk_launchers(
    own_parent: impl Fn() -> i32,
    identify: impl Fn(i32) -> Result<ClientIdentity, PeerError>,
    parent: impl Fn(i32) -> Option<i32>,
) -> Result<ClientIdentity, PeerError> {
    let mut child: Option<i32> = None;
    let mut pid = own_parent();
    let mut chain = Vec::new();
    for _ in 0..=MAX_LAUNCHERS {
        if pid <= 1 {
            return Err(PeerError::Unreadable("no client process"));
        }
        let mut id = identify(pid)?;
        let parent_now = match child {
            None => Some(own_parent()),
            Some(c) => parent(c),
        };
        if parent_now != Some(pid) {
            return Err(PeerError::Gone);
        }
        if id.code.is_init() {
            return Err(PeerError::Unreadable("no client process"));
        }
        chain.push(id.code.client_id());
        if !id.code.is_launcher() {
            id.chain = chain;
            return Ok(id);
        }
        child = Some(pid);
        pid = parent(pid).ok_or(PeerError::Gone)?;
    }
    Err(PeerError::Unreadable("too many launchers"))
}

#[cfg(target_os = "macos")]
fn identify_macos(guest: crate::macos::Guest, pid: i32) -> Result<ClientIdentity, PeerError> {
    let (code, path) = crate::macos::identify_running(guest)?;
    // The path is informative. With an audit token, a path read by pid
    // could name another process: only the code object's own path is used.
    let exe = match guest {
        crate::macos::Guest::Pid(_) => path.or_else(|| crate::cred::exe_path(pid)),
        crate::macos::Guest::AuditToken(..) => path,
    };
    Ok(ClientIdentity {
        code,
        pid,
        exe,
        chain: Vec::new(),
    })
}

/// Without code signatures, a process is its running image, hashed through
/// `/proc/<pid>/exe`, which stays bound to it even if its path is replaced.
#[cfg(not(target_os = "macos"))]
fn identify_unsigned(pid: i32) -> Result<ClientIdentity, PeerError> {
    let alive = || Path::new(&format!("/proc/{pid}")).exists();
    let Some(path) = crate::cred::exe_path(pid) else {
        return Err(if alive() {
            PeerError::Unreadable("executable path")
        } else {
            PeerError::Gone
        });
    };
    let sha256 = file_sha256(Path::new(&format!("/proc/{pid}/exe"))).map_err(|_| {
        if alive() {
            PeerError::Unreadable("executable hash")
        } else {
            PeerError::Gone
        }
    })?;
    Ok(ClientIdentity {
        code: CodeIdentity::Unsigned {
            path: path.clone(),
            sha256,
        },
        pid,
        exe: Some(path),
        chain: Vec::new(),
    })
}

/// Lowercase hex SHA-256 of the file at `path`.
pub fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(data_encoding::HEXLOWER.encode(ctx.finish().as_ref()))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn with(pid: i32, code: CodeIdentity) -> ClientIdentity {
        ClientIdentity {
            code,
            pid,
            exe: None,
            chain: Vec::new(),
        }
    }

    fn platform(pid: i32, identifier: &str) -> ClientIdentity {
        with(
            pid,
            CodeIdentity::Platform {
                identifier: identifier.into(),
            },
        )
    }

    fn unsigned(pid: i32, path: &str) -> ClientIdentity {
        with(
            pid,
            CodeIdentity::Unsigned {
                path: path.into(),
                sha256: format!("{pid:064}"),
            },
        )
    }

    /// Process tree where the parent of `p` is `p + 1`, this process's
    /// parent being 10.
    fn up(pid: i32) -> Option<i32> {
        Some(pid + 1)
    }

    #[test]
    fn walk_skips_launchers_and_records_the_chain() {
        // 10 (zsh) -> 11 (env) -> 12 (client) -> 13
        let ids = |pid| {
            Ok(match pid {
                10 => platform(pid, "com.apple.zsh"),
                11 => platform(pid, "com.apple.env"),
                _ => platform(pid, "com.example.host"),
            })
        };
        let id = walk_launchers(|| 10, ids, up).expect("client");
        assert_eq!(id.pid, 12);
        assert_eq!(
            id.chain,
            [
                "platform:com.apple.zsh",
                "platform:com.apple.env",
                "platform:com.example.host"
            ]
        );
    }

    #[test]
    fn walk_skips_linux_launchers_by_path() {
        let ids = |pid| {
            Ok(match pid {
                10 => unsigned(pid, "/usr/bin/dash (deleted)"),
                11 => unsigned(pid, "/usr/bin/env"),
                _ => unsigned(pid, "/usr/lib/host/host"),
            })
        };
        let id = walk_launchers(|| 10, ids, up).expect("client");
        assert_eq!(id.pid, 12);
        assert_eq!(id.chain.len(), 3);
    }

    #[test]
    fn walk_refuses_init_as_client() {
        let ids = |pid| {
            Ok(match pid {
                10 => unsigned(pid, "/bin/sh"),
                _ => unsigned(pid, "/usr/lib/systemd/systemd"),
            })
        };
        assert_eq!(
            walk_launchers(|| 10, ids, up),
            Err(PeerError::Unreadable("no client process"))
        );
    }

    #[test]
    fn walk_stops_after_eight_launchers() {
        let all_sh = |pid| Ok(platform(pid, "com.apple.sh"));
        // Eight launchers then a client: found.
        let eight = |pid| {
            if pid < 10 + MAX_LAUNCHERS as i32 {
                all_sh(pid)
            } else {
                Ok(platform(pid, "com.example.host"))
            }
        };
        let id = walk_launchers(|| 10, eight, up).expect("client");
        assert_eq!(id.chain.len(), MAX_LAUNCHERS + 1);
        // Nine launchers: refused, never a launcher as the client.
        assert_eq!(
            walk_launchers(|| 10, all_sh, up),
            Err(PeerError::Unreadable("too many launchers"))
        );
    }

    #[test]
    fn walk_refuses_orphans_and_lost_parents() {
        let sh = |pid| Ok(platform(pid, "com.apple.sh"));
        assert_eq!(
            walk_launchers(|| 10, sh, |_| Some(1)),
            Err(PeerError::Unreadable("no client process"))
        );
        assert_eq!(walk_launchers(|| 10, sh, |_| None), Err(PeerError::Gone));
        assert_eq!(
            walk_launchers(|| 1, sh, |_| None),
            Err(PeerError::Unreadable("no client process"))
        );
    }

    #[test]
    fn walk_detects_a_parent_that_changed_during_identification() {
        let host = |pid| Ok(platform(pid, "com.example.host"));
        // This process's parent exits while being identified: reparented.
        let calls = Cell::new(0);
        let own_parent = || {
            calls.set(calls.get() + 1);
            if calls.get() == 1 { 10 } else { 1 }
        };
        assert_eq!(walk_launchers(own_parent, host, up), Err(PeerError::Gone));

        // A launcher's parent changes between the read and the check.
        let ids = |pid| {
            Ok(match pid {
                10 => platform(pid, "com.apple.sh"),
                _ => platform(pid, "com.example.host"),
            })
        };
        let reads = Cell::new(0);
        let parent = |pid: i32| {
            reads.set(reads.get() + 1);
            Some(if reads.get() == 1 { pid + 1 } else { 99 })
        };
        assert_eq!(walk_launchers(|| 10, ids, parent), Err(PeerError::Gone));
    }
}
