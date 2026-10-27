//! Kernel credentials of local processes.
//!
//! Each `unsafe` block wraps one libc call, either without arguments or on a
//! file descriptor borrowed from a live `UnixStream`, with out-pointers to
//! properly sized locals whose size is passed alongside.
#![allow(unsafe_code)]

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// What the kernel says about the process at the other end of a Unix
/// socket. Each part is `None` when the platform or the kernel cannot tell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerCred {
    /// Effective uid of the peer.
    pub uid: Option<u32>,
    /// Pid of the peer at connection time.
    pub pid: Option<i32>,
    /// macOS audit token of the peer (`LOCAL_PEERTOKEN`): names the process
    /// and its pid version, so it cannot be confused with a reused pid.
    pub audit_token: Option<[u8; 32]>,
}

/// Credentials of the peer of `s`.
pub fn peer_cred(s: &UnixStream) -> PeerCred {
    PeerCred {
        uid: peer_uid(s),
        pid: peer_pid(s),
        audit_token: peer_audit_token(s),
    }
}

/// Pid of this process's parent.
pub fn parent_pid() -> i32 {
    // SAFETY: getppid takes no argument, cannot fail and has no side effect.
    unsafe { libc::getppid() }
}

/// True if a process with this pid exists: `kill(pid, 0)` succeeds, or
/// fails with `EPERM` (it exists but belongs to another user). Pids that are
/// not positive never name one process and give `false`.
pub fn pid_exists(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill with signal 0 sends nothing, only checks that `pid`
    // names a process this one could signal; `pid > 0` so it never targets
    // a process group.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Effective uid of this process.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no argument, cannot fail and has no side effect.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "macos")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor belongs to `s`, which outlives the call; `uid`
    // and `gid` are valid, writable locals of the types getpeereid expects.
    let rc = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

/// Reads a fixed-size `SOL_LOCAL` socket option of `s` into a `T`.
#[cfg(target_os = "macos")]
fn local_sockopt<T: Copy>(s: &UnixStream, option: libc::c_int, mut value: T) -> Option<T> {
    let size = std::mem::size_of::<T>();
    let mut len = size as libc::socklen_t;
    // SAFETY: the descriptor belongs to `s`, which outlives the call; `value`
    // is a writable local of `size` bytes and `len` holds that exact size,
    // so the kernel writes at most `len` bytes into it. `T: Copy` is only
    // instantiated with plain integers and byte arrays, for which any bit
    // pattern written by the kernel is a valid value.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_LOCAL,
            option,
            (&mut value as *mut T).cast::<libc::c_void>(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == size).then_some(value)
}

#[cfg(target_os = "macos")]
fn peer_pid(s: &UnixStream) -> Option<i32> {
    local_sockopt::<libc::pid_t>(s, libc::LOCAL_PEERPID, 0).filter(|&p| p > 0)
}

#[cfg(target_os = "macos")]
fn peer_audit_token(s: &UnixStream) -> Option<[u8; 32]> {
    // LOCAL_PEERTOKEN fills an audit_token_t: eight 32-bit words.
    local_sockopt::<[u8; 32]>(s, libc::LOCAL_PEERTOKEN, [0; 32])
}

/// Parent pid of `pid`, `None` when the process is gone or unreadable.
#[cfg(target_os = "macos")]
pub fn parent_of(pid: i32) -> Option<i32> {
    // SAFETY: proc_bsdinfo is a plain C struct of integers and byte arrays,
    // for which all-zero bytes are a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is a writable proc_bsdinfo of exactly `size` bytes, the
    // buffer size passed; PROC_PIDTBSDINFO writes at most that many bytes and
    // returns how many it wrote, or <= 0 on failure.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast::<libc::c_void>(),
            size,
        )
    };
    (n == size).then_some(info.pbi_ppid as i32)
}

/// Executable path of `pid`. Informative: a pid can be reused.
#[cfg(target_os = "macos")]
pub fn exe_path(pid: i32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is a writable buffer of exactly the size passed, which
    // proc_pidpath never writes past; it returns the path length or <= 0.
    let n = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

#[cfg(target_os = "linux")]
fn linux_peer_cred(s: &UnixStream) -> Option<libc::ucred> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor belongs to `s`, which outlives the call; `cred`
    // is a writable `ucred` and `len` holds its exact size, so the kernel
    // writes at most `len` bytes into it.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == std::mem::size_of::<libc::ucred>()).then_some(cred)
}

#[cfg(target_os = "linux")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    linux_peer_cred(s).map(|c| c.uid)
}

#[cfg(target_os = "linux")]
fn peer_pid(s: &UnixStream) -> Option<i32> {
    linux_peer_cred(s).map(|c| c.pid).filter(|&p| p > 0)
}

#[cfg(not(target_os = "macos"))]
fn peer_audit_token(_s: &UnixStream) -> Option<[u8; 32]> {
    None
}

/// Parent pid of `pid`, `None` when the process is gone or unreadable.
#[cfg(target_os = "linux")]
pub fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat_ppid(&stat)
}

/// Parent pid in the contents of `/proc/<pid>/stat`: the fourth field, read
/// after the last `)` because the command name may hold spaces and parens.
#[cfg(any(target_os = "linux", test))]
fn parse_stat_ppid(stat: &str) -> Option<i32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut fields = rest.split_ascii_whitespace();
    let state = fields.next()?;
    let ppid: i32 = fields.next()?.parse().ok()?;
    // A zombie or a reaped process is not a parent anyone can identify.
    (state != "Z" && state != "X").then_some(ppid)
}

/// Executable path of `pid`. Informative: a pid can be reused.
#[cfg(target_os = "linux")]
pub fn exe_path(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_uid(_s: &UnixStream) -> Option<u32> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_pid(_s: &UnixStream) -> Option<i32> {
    None
}

/// Parent pid of `pid`: unknown on this platform.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn parent_of(_pid: i32) -> Option<i32> {
    None
}

/// Executable path of `pid`: unknown on this platform.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn exe_path(_pid: i32) -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::{parse_stat_ppid, pid_exists};

    #[test]
    fn pid_exists_for_live_and_foreign_pids_only() {
        assert!(pid_exists(std::process::id() as i32));
        // pid 1 belongs to root: EPERM still means it exists.
        assert!(pid_exists(1));
        assert!(!pid_exists(0));
        assert!(!pid_exists(-1));
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id() as i32;
        child.wait().unwrap();
        assert!(!pid_exists(pid));
    }

    #[test]
    fn stat_ppid_survives_odd_command_names() {
        assert_eq!(parse_stat_ppid("42 (a) b) c) S 7 42 42 0"), Some(7));
        assert_eq!(parse_stat_ppid("42 (sleep) Z 7 42"), None);
        assert_eq!(parse_stat_ppid("garbage"), None);
    }
}
