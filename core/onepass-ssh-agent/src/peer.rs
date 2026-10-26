//! Credentials of the process at the other end of an agent socket (spec
//! 6.3): uid, pid and executable path.
//!
//! This is the only module of the crate with `unsafe` code: each block wraps
//! one libc call on a file descriptor borrowed from a live `UnixStream`, with
//! out-pointers to properly sized locals.
#![allow(unsafe_code)]

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

/// What the kernel says about a connected client. Each part is `None` when
/// the platform or the kernel cannot tell.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerInfo {
    /// Effective uid of the peer.
    pub uid: Option<u32>,
    /// Pid of the peer (at connection time).
    pub pid: Option<i32>,
    /// Executable path of that pid. Informative: a pid can be reused.
    pub exe: Option<String>,
}

/// Credentials of the peer of `s`.
pub fn peer_info(s: &UnixStream) -> PeerInfo {
    let pid = peer_pid(s);
    PeerInfo {
        uid: peer_uid(s),
        pid,
        exe: pid.and_then(exe_of),
    }
}

/// Effective uid of this process.
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no argument, cannot fail and has no side effect.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "macos")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor belongs to `s`, which outlives the call; `uid`
    // and `gid` are valid, writable locals of the types getpeereid expects.
    let rc = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

#[cfg(target_os = "macos")]
fn peer_pid(s: &UnixStream) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: the descriptor belongs to `s`, which outlives the call; `pid`
    // is a writable `pid_t` and `len` holds its exact size, so the kernel
    // writes at most `len` bytes into it.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast::<libc::c_void>(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == std::mem::size_of::<libc::pid_t>() && pid > 0).then_some(pid)
}

#[cfg(target_os = "macos")]
fn exe_of(pid: i32) -> Option<String> {
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
    String::from_utf8(buf).ok()
}

#[cfg(target_os = "linux")]
fn peer_cred(s: &UnixStream) -> Option<libc::ucred> {
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
    peer_cred(s).map(|c| c.uid)
}

#[cfg(target_os = "linux")]
fn peer_pid(s: &UnixStream) -> Option<i32> {
    peer_cred(s).map(|c| c.pid).filter(|&p| p > 0)
}

#[cfg(target_os = "linux")]
fn exe_of(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_uid(_s: &UnixStream) -> Option<u32> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_pid(_s: &UnixStream) -> Option<i32> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn exe_of(_pid: i32) -> Option<String> {
    None
}
