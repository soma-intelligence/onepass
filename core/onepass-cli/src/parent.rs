//! Name of the program that started the CLI, for the key-use log.
//!
//! The log shows which application asked for a secret ("Terminal", "zsh",
//! "python3"). Only the base name of the executable is kept: never its path
//! and never the command line or the arguments, which can hold secrets.
//! Nothing is run to find it (no `ps`): the system is asked directly.

/// Base name of the parent process, or an empty string when it cannot be
/// found (the process is gone, or the system refuses to say).
pub fn parent_process_name() -> String {
    // SAFETY: getppid has no preconditions and cannot fail.
    let ppid = unsafe { libc::getppid() };
    if ppid <= 0 {
        return String::new();
    }
    name_of(ppid)
}

/// The path of the executable of `pid`, which `proc_pidpath` fills in.
#[cfg(target_os = "macos")]
fn name_of(pid: libc::pid_t) -> String {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is valid for the `buffersize` bytes given.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return String::new();
    }
    buf.truncate(n as usize);
    base_name(&String::from_utf8_lossy(&buf))
}

/// `/proc/<pid>/comm`: the name the kernel keeps, 15 characters at most.
#[cfg(target_os = "linux")]
fn name_of(pid: libc::pid_t) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn name_of(_pid: libc::pid_t) -> String {
    String::new()
}

#[cfg(any(target_os = "macos", test))]
fn base_name(path: &str) -> String {
    path.rsplit('/')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_name_drops_the_directories() {
        assert_eq!(base_name("/usr/bin/zsh"), "zsh");
        assert_eq!(
            base_name("/Applications/Some App.app/Contents/MacOS/Some App"),
            "Some App"
        );
        assert_eq!(base_name("zsh"), "zsh");
        assert_eq!(base_name(""), "");
    }

    #[test]
    fn the_parent_of_the_test_binary_has_a_name() {
        // `cargo test` (or the shell running the binary) is the parent.
        assert!(!parent_process_name().is_empty());
    }
}
