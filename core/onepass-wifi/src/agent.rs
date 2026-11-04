//! The login item that runs `onepass wifi watch`, per user, no
//! administrator:
//!
//! - Linux: a systemd user unit, `<config>/systemd/user/onepass-wifi.service`,
//!   enabled and started at once (`systemctl --user enable --now`).
//! - Windows: the `OnePassWiFi` value of the user's `Run` key (a logon
//!   scheduled task needs an administrator), then started at once.

use std::fs;
use std::path::{Path, PathBuf};

use crate::exec::{Exec, SystemExec};
use crate::{Result, WifiError, linux, windows};

/// Name of the systemd user unit.
pub const UNIT: &str = "onepass-wifi.service";

/// `ExecStart` of the unit: the executable and its arguments, each quoted.
pub fn exec_start(exe: &Path, args: &[String]) -> String {
    let mut words = vec![linux::systemd_quote(&exe.to_string_lossy())];
    words.extend(args.iter().map(|a| linux::systemd_quote(a)));
    words.join(" ")
}

/// The Windows command line of the `Run` value: every word in double
/// quotes (Windows paths cannot hold one; other words with one are
/// refused).
pub fn windows_command(exe: &Path, args: &[String]) -> Result<String> {
    let mut words = vec![exe.to_string_lossy().into_owned()];
    words.extend(args.iter().cloned());
    let mut out = Vec::new();
    for w in words {
        if w.contains('"') {
            return Err(WifiError::new("argument with a double quote"));
        }
        // `\"` would read as a literal quote and run the words together.
        if w.ends_with('\\') {
            return Err(WifiError::new("argument ending with a backslash"));
        }
        out.push(format!("\"{w}\""));
    }
    Ok(out.join(" "))
}

/// Where the unit goes: `<config>/systemd/user/onepass-wifi.service`.
pub fn unit_path() -> Result<PathBuf> {
    crate::state::config_dir()
        .map(|d| d.join("systemd").join("user").join(UNIT))
        .ok_or_else(|| WifiError::new("no configuration directory"))
}

fn systemctl() -> PathBuf {
    ["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("/usr/bin/systemctl"))
}

fn run_ok(exec: &mut dyn Exec, program: &Path, args: &[&str], what: &str) -> Result<()> {
    let a: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    if exec.run(program, &a)?.ok {
        Ok(())
    } else {
        Err(WifiError::new(format!("{what} failed")))
    }
}

/// Install and start the login item running `exe args...`.
pub fn install(exe: &Path, args: &[String]) -> Result<String> {
    if cfg!(windows) {
        return install_windows(exe, args);
    }
    if !cfg!(target_os = "linux") {
        return Err(WifiError::new(
            "the Wi-Fi agent runs on Windows and Linux; on a Mac the app does it",
        ));
    }
    let path = unit_path()?;
    let dir = path
        .parent()
        .ok_or_else(|| WifiError::new("bad unit path"))?;
    fs::create_dir_all(dir).map_err(|_| WifiError::new("cannot create the unit directory"))?;
    fs::write(&path, linux::systemd_unit(&exec_start(exe, args)))
        .map_err(|_| WifiError::new("cannot write the unit"))?;
    let sc = systemctl();
    let mut exec = SystemExec;
    run_ok(
        &mut exec,
        &sc,
        &["--user", "daemon-reload"],
        "systemctl daemon-reload",
    )?;
    run_ok(
        &mut exec,
        &sc,
        &["--user", "enable", "--now", UNIT],
        "systemctl enable",
    )?;
    Ok(path.display().to_string())
}

/// Stop and remove the login item.
pub fn uninstall() -> Result<()> {
    if cfg!(windows) {
        return uninstall_windows();
    }
    if !cfg!(target_os = "linux") {
        return Err(WifiError::new("the Wi-Fi agent runs on Windows and Linux"));
    }
    let sc = systemctl();
    let mut exec = SystemExec;
    // Not installed is fine.
    let _ = run_ok(&mut exec, &sc, &["--user", "disable", "--now", UNIT], "");
    let path = unit_path()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|_| WifiError::new("cannot remove the unit"))?;
    }
    let _ = run_ok(&mut exec, &sc, &["--user", "daemon-reload"], "");
    Ok(())
}

fn reg_exe() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join("reg.exe")
}

fn install_windows(exe: &Path, args: &[String]) -> Result<String> {
    let command = windows_command(exe, args)?;
    // reg.exe reads its arguments with the C runtime rules: `\"` inside
    // the quoted data is a literal quote.
    let data = format!("\"{}\"", command.replace('"', "\\\""));
    let a = vec![
        "add".to_owned(),
        format!("\"{}\"", windows::RUN_KEY),
        "/v".to_owned(),
        windows::RUN_VALUE.to_owned(),
        "/t".to_owned(),
        "REG_SZ".to_owned(),
        "/d".to_owned(),
        data,
        "/f".to_owned(),
    ];
    if !SystemExec.run(&reg_exe(), &a)?.ok {
        return Err(WifiError::new("reg add failed"));
    }
    start_now_windows(exe, args)?;
    Ok(format!("{}\\{}", windows::RUN_KEY, windows::RUN_VALUE))
}

#[cfg(windows)]
fn start_now_windows(exe: &Path, args: &[String]) -> Result<()> {
    use std::os::windows::process::CommandExt;
    // CREATE_NEW_CONSOLE: its own window, where it asks the password once.
    std::process::Command::new(exe)
        .args(args)
        .creation_flags(0x0000_0010)
        .spawn()
        .map(|_| ())
        .map_err(|_| WifiError::new("cannot start the Wi-Fi agent"))
}

#[cfg(not(windows))]
fn start_now_windows(_: &Path, _: &[String]) -> Result<()> {
    Ok(())
}

fn uninstall_windows() -> Result<()> {
    let a = vec![
        "delete".to_owned(),
        format!("\"{}\"", windows::RUN_KEY),
        "/v".to_owned(),
        windows::RUN_VALUE.to_owned(),
        "/f".to_owned(),
    ];
    // Absent is fine.
    let _ = SystemExec.run(&reg_exe(), &a)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines() {
        let args = vec!["--data-dir".to_owned(), "/home/a b/%x".to_owned()];
        assert_eq!(
            exec_start(Path::new("/usr/local/bin/onepass"), &args),
            "\"/usr/local/bin/onepass\" \"--data-dir\" \"/home/a b/%%x\""
        );
        assert_eq!(
            windows_command(Path::new("C:\\Program Files\\OnePass\\onepass.exe"), &args).unwrap(),
            "\"C:\\Program Files\\OnePass\\onepass.exe\" \"--data-dir\" \"/home/a b/%x\""
        );
        assert!(windows_command(Path::new("x"), &["a\"b".to_owned()]).is_err());
        assert!(windows_command(Path::new("x"), &["C:\\data\\".to_owned()]).is_err());
    }
}
