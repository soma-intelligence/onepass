//! Code-signing identity of local clients.

use std::path::{Path, PathBuf};

use std::io::Read;

use crate::cred::{PeerCred, exe_path, parent_of, parent_pid};

/// Identifiers of the system launchers skipped when looking for the MCP
/// client (spec 3.2).
pub const LAUNCHERS: [&str; 5] = [
    "com.apple.sh",
    "com.apple.bash",
    "com.apple.zsh",
    "com.apple.dash",
    "com.apple.env",
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
    /// Unsigned, ad hoc signed or with a signature that does not verify:
    /// pinned by the SHA-256 of its executable file.
    Unsigned { path: PathBuf, sha256: String },
}

impl CodeIdentity {
    /// Stable client id: `platform:<identifier>`,
    /// `team:<team_id>:<identifier>` or `unsigned:<sha256 hex>`.
    pub fn client_id(&self) -> String {
        match self {
            CodeIdentity::Platform { identifier } => format!("platform:{identifier}"),
            CodeIdentity::Team {
                team_id,
                identifier,
            } => format!("team:{team_id}:{identifier}"),
            CodeIdentity::Unsigned { sha256, .. } => format!("unsigned:{sha256}"),
        }
    }

    /// Whether the system vouches for the code (platform or team).
    pub fn is_signed(&self) -> bool {
        !matches!(self, CodeIdentity::Unsigned { .. })
    }

    /// Whether this is a system launcher skipped above the MCP server.
    fn is_launcher(&self) -> bool {
        matches!(self, CodeIdentity::Platform { identifier } if LAUNCHERS.contains(&identifier.as_str()))
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
    /// The system would not tell: the reason names the failed step.
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
        return identify_macos(crate::macos::Guest::AuditToken(token), pid);
    }
    identify_pid(pid)
}

/// Identity of the MCP client: the first ancestor of this process that is
/// not a launcher (spec 3.2), with the client ids of the ancestors walked.
pub fn identify_mcp_parent() -> Result<ClientIdentity, PeerError> {
    walk_launchers(parent_pid(), identify_pid, parent_of)
}

/// From `start` upwards, skips at most [`MAX_LAUNCHERS`] launchers and
/// returns the first other process. Fails rather than settle for a
/// launcher, for pid 1 (an orphan's adoptive parent, not its launcher) or
/// for an ancestor that cannot be read.
fn walk_launchers(
    start: i32,
    identify: impl Fn(i32) -> Result<ClientIdentity, PeerError>,
    parent: impl Fn(i32) -> Option<i32>,
) -> Result<ClientIdentity, PeerError> {
    let mut pid = start;
    let mut chain = Vec::new();
    for _ in 0..=MAX_LAUNCHERS {
        if pid <= 1 {
            return Err(PeerError::Unreadable("orphaned client"));
        }
        let mut id = identify(pid)?;
        chain.push(id.code.client_id());
        if !id.code.is_launcher() {
            id.chain = chain;
            return Ok(id);
        }
        pid = parent(pid).ok_or(PeerError::Gone)?;
    }
    Err(PeerError::Unreadable("too many launchers"))
}

#[cfg(target_os = "macos")]
fn identify_macos(guest: crate::macos::Guest, pid: i32) -> Result<ClientIdentity, PeerError> {
    use crate::macos::{Signature, signature_of};
    let (signature, path) = signature_of(guest)?;
    let exe = path.or_else(|| exe_path(pid));
    let code = match signature {
        Signature::Platform { identifier } => CodeIdentity::Platform { identifier },
        Signature::Team {
            team_id,
            identifier,
        } => CodeIdentity::Team {
            team_id,
            identifier,
        },
        Signature::Unsigned => {
            let path = exe
                .clone()
                .ok_or(PeerError::Unreadable("executable path"))?;
            let sha256 =
                file_sha256(&path).map_err(|_| PeerError::Unreadable("executable hash"))?;
            CodeIdentity::Unsigned { path, sha256 }
        }
    };
    Ok(ClientIdentity {
        code,
        pid,
        exe,
        chain: Vec::new(),
    })
}

/// Without code signatures, a process is its executable file. On Linux the
/// file is hashed through `/proc/<pid>/exe`, which stays bound to the
/// running image even if its path is replaced.
#[cfg(not(target_os = "macos"))]
fn identify_unsigned(pid: i32) -> Result<ClientIdentity, PeerError> {
    let alive = || std::path::Path::new(&format!("/proc/{pid}")).exists();
    let Some(path) = exe_path(pid) else {
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
    use super::*;

    fn platform(pid: i32, identifier: &str) -> ClientIdentity {
        ClientIdentity {
            code: CodeIdentity::Platform {
                identifier: identifier.into(),
            },
            pid,
            exe: None,
            chain: Vec::new(),
        }
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
        let id = walk_launchers(10, ids, |pid| Some(pid + 1)).expect("client");
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
        let id = walk_launchers(10, eight, |pid| Some(pid + 1)).expect("client");
        assert_eq!(id.chain.len(), MAX_LAUNCHERS + 1);
        // Nine launchers: refused, never a launcher as the client.
        assert_eq!(
            walk_launchers(10, all_sh, |pid| Some(pid + 1)),
            Err(PeerError::Unreadable("too many launchers"))
        );
    }

    #[test]
    fn walk_refuses_orphans_and_lost_parents() {
        let sh = |pid| Ok(platform(pid, "com.apple.sh"));
        assert_eq!(
            walk_launchers(10, sh, |_| Some(1)),
            Err(PeerError::Unreadable("orphaned client"))
        );
        assert_eq!(walk_launchers(10, sh, |_| None), Err(PeerError::Gone));
        assert_eq!(
            walk_launchers(1, sh, |_| None),
            Err(PeerError::Unreadable("orphaned client"))
        );
    }
}
