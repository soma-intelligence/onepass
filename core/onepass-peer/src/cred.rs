//! Kernel credentials of local processes.
//!
//! Each `unsafe` block wraps one libc call, either without arguments or on a
//! file descriptor borrowed from a live `UnixStream`, with out-pointers to
//! properly sized locals whose size is passed alongside. On Windows each one
//! wraps one Win32 call on a handle it opened and closes (`windows` below).
#![allow(unsafe_code)]

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
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
#[cfg(unix)]
pub fn peer_cred(s: &UnixStream) -> PeerCred {
    PeerCred {
        uid: peer_uid(s),
        pid: peer_pid(s),
        audit_token: peer_audit_token(s),
    }
}

/// Pid of this process's parent.
#[cfg(unix)]
pub fn parent_pid() -> i32 {
    // SAFETY: getppid takes no argument, cannot fail and has no side effect.
    unsafe { libc::getppid() }
}

/// True if a process with this pid exists: `kill(pid, 0)` succeeds, or
/// fails with `EPERM` (it exists but belongs to another user). Pids that are
/// not positive never name one process and give `false`.
#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(any(target_os = "linux", target_os = "android"))]
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

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    linux_peer_cred(s).map(|c| c.uid)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_pid(s: &UnixStream) -> Option<i32> {
    linux_peer_cred(s).map(|c| c.pid).filter(|&p| p > 0)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn peer_audit_token(_s: &UnixStream) -> Option<[u8; 32]> {
    None
}

/// Parent pid of `pid`, `None` when the process is gone or unreadable.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_stat_ppid(&stat)
}

/// Parent pid in the contents of `/proc/<pid>/stat`: the fourth field, read
/// after the last `)` because the command name may hold spaces and parens.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_stat_ppid(stat: &str) -> Option<i32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut fields = rest.split_ascii_whitespace();
    let state = fields.next()?;
    let ppid: i32 = fields.next()?.parse().ok()?;
    // A zombie or a reaped process is not a parent anyone can identify.
    (state != "Z" && state != "X").then_some(ppid)
}

/// Executable path of `pid`. Informative: a pid can be reused.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn exe_path(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "linux", target_os = "android"))
))]
fn peer_uid(_s: &UnixStream) -> Option<u32> {
    None
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "linux", target_os = "android"))
))]
fn peer_pid(_s: &UnixStream) -> Option<i32> {
    None
}

/// Parent pid of `pid`: unknown on this platform.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "linux", target_os = "android"))
))]
pub fn parent_of(_pid: i32) -> Option<i32> {
    None
}

/// Executable path of `pid`: unknown on this platform.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "linux", target_os = "android"))
))]
pub fn exe_path(_pid: i32) -> Option<PathBuf> {
    None
}

// ---- Windows (spec 2026-10-30 section 9) -------------------------------------
//
// No Unix socket and no uid: the peer of a named pipe is identified by
// `GetNamedPipeClientProcessId` in the server that owns the pipe (milestone
// X3). Here: parent pids, liveness and image paths of processes.

#[cfg(windows)]
pub use windows::{effective_uid, exe_path, parent_of, parent_pid, pid_exists};

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, STILL_ACTIVE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, GetExitCodeProcess, OpenProcess, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    /// A handle closed on drop.
    struct Owned(HANDLE);

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the handle was returned open by the call that made
            // this value and is closed exactly once, here.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open(pid: i32) -> Option<Owned> {
        let pid = u32::try_from(pid).ok().filter(|&p| p > 0)?;
        // SAFETY: no pointer argument; a null result means failure.
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        (!h.is_null()).then_some(Owned(h))
    }

    /// No uid on Windows: always 0. Callers that compare it with a peer's
    /// uid never get one there (no Unix socket peer).
    pub fn effective_uid() -> u32 {
        0
    }

    /// Pid of this process's parent, 0 when Windows no longer lists it.
    pub fn parent_pid() -> i32 {
        // SAFETY: no argument, cannot fail.
        let me = unsafe { GetCurrentProcessId() };
        i32::try_from(me).ok().and_then(parent_of).unwrap_or(0)
    }

    /// Parent pid of `pid` from a process snapshot. Informative: Windows
    /// reuses pids and keeps a parent pid after the parent exits.
    pub fn parent_of(pid: i32) -> Option<i32> {
        let pid = u32::try_from(pid).ok().filter(|&p| p > 0)?;
        // SAFETY: no pointer argument; INVALID_HANDLE_VALUE means failure.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let snap = Owned(snap);
        // SAFETY: PROCESSENTRY32W is plain integers and a u16 array, valid
        // when zeroed; dwSize is set before the first call as required.
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: `snap` is a live snapshot, `entry` a writable entry of the
        // size announced in dwSize.
        let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) };
        while ok != 0 {
            if entry.th32ProcessID == pid {
                return i32::try_from(entry.th32ParentProcessID).ok();
            }
            // SAFETY: as above.
            ok = unsafe { Process32NextW(snap.0, &mut entry) };
        }
        None
    }

    /// True if `pid` names a process that has not exited.
    pub fn pid_exists(pid: i32) -> bool {
        let Some(h) = open(pid) else {
            return false;
        };
        let mut code = 0u32;
        // SAFETY: `h` is a live process handle, `code` a writable u32.
        let ok = unsafe { GetExitCodeProcess(h.0, &mut code) };
        ok != 0 && code == STILL_ACTIVE as u32
    }

    /// Image path of `pid`. Informative: a pid can be reused.
    pub fn exe_path(pid: i32) -> Option<PathBuf> {
        let h = open(pid)?;
        let mut buf = vec![0u16; 32 * 1024];
        let mut len = buf.len() as u32;
        // SAFETY: `h` is a live process handle; `buf` holds `len` u16s and
        // the call writes at most that many, then stores the length used.
        let ok = unsafe {
            QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        };
        if ok == 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(PathBuf::from(OsString::from_wide(&buf)))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_stat_ppid;
    #[cfg(unix)]
    use super::pid_exists;

    #[cfg(unix)]
    #[test]
    fn pid_exists_for_live_and_foreign_pids_only() {
        assert!(pid_exists(std::process::id() as i32));
        // pid 1 belongs to root: EPERM still means it exists.
        assert!(pid_exists(1));
        assert!(!pid_exists(0));
        assert!(!pid_exists(-1));
        // Android keeps its tools in /system/bin.
        let true_program = if cfg!(target_os = "android") {
            "/system/bin/true"
        } else {
            "/usr/bin/true"
        };
        let mut child = std::process::Command::new(true_program).spawn().unwrap();
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

    #[cfg(windows)]
    #[test]
    fn windows_process_queries() {
        let me = std::process::id() as i32;
        assert!(super::pid_exists(me));
        assert!(!super::pid_exists(0));
        assert!(!super::pid_exists(-1));
        assert!(super::parent_pid() > 0);
        let exe = super::exe_path(me).unwrap();
        assert_eq!(
            exe.canonicalize().unwrap(),
            std::env::current_exe().unwrap().canonicalize().unwrap()
        );
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit"])
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert_eq!(super::parent_of(pid), Some(me));
        child.wait().unwrap();
        assert!(!super::pid_exists(pid));
    }
}
