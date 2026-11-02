//! Finding and launching Chromium with a fresh profile and the DevTools endpoint on a free port.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `--chrome`, else `$CHROME`, else Playwright's Chromium in the local cache.
pub fn find_chrome(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.exists().then(|| p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("CHROME").map(PathBuf::from) {
        return p.exists().then_some(p);
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let caches = [
        home.join("Library/Caches/ms-playwright"),
        home.join(".cache/ms-playwright"),
    ];
    let tails = [
        "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
        "chrome-linux64/chrome",
        "chrome-linux/chrome",
    ];
    for cache in caches {
        let Ok(rd) = std::fs::read_dir(&cache) else {
            continue;
        };
        let mut dirs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("chromium-"))
            })
            .collect();
        dirs.sort();
        for d in dirs.iter().rev() {
            for t in tails {
                let p = d.join(t);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// The DevTools browser endpoint in a line of Chromium's stderr.
pub fn endpoint_of(line: &str) -> Option<String> {
    line.split_once("DevTools listening on ")
        .map(|(_, u)| u.trim().to_string())
        .filter(|u| u.starts_with("ws://"))
}

pub struct Chrome {
    child: Child,
    profile: PathBuf,
    pub ws_url: String,
}

impl Chrome {
    pub fn launch(binary: &Path) -> Result<Chrome, String> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let profile =
            std::env::temp_dir().join(format!("onepass-bench-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&profile).map_err(|e| format!("profile dir: {e}"))?;
        let mut child = Command::new(binary)
            .args([
                "--headless=new",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--disable-default-apps",
                "--metrics-recording-only",
                "--password-store=basic",
                "--use-mock-keychain",
                "--window-size=1280,900",
            ])
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("launch {}: {e}", binary.display()))?;
        let stderr = child.stderr.take().ok_or("no stderr")?;
        let (tx, rx) = mpsc::channel();
        // Keeps draining stderr for the life of the browser, so it never blocks on a full pipe.
        std::thread::spawn(move || {
            let mut sent = false;
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if !sent && let Some(u) = endpoint_of(&line) {
                    let _ = tx.send(u);
                    sent = true;
                }
            }
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(ws_url) => Ok(Chrome {
                child,
                profile,
                ws_url,
            }),
            Err(_) => {
                let _ = child.kill();
                let _ = std::fs::remove_dir_all(&profile);
                Err("Chromium did not print its DevTools endpoint in 30 s".into())
            }
        }
    }
}

impl Drop for Chrome {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.profile);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_endpoint_line() {
        assert_eq!(
            endpoint_of("DevTools listening on ws://127.0.0.1:53211/devtools/browser/ab-cd"),
            Some("ws://127.0.0.1:53211/devtools/browser/ab-cd".into())
        );
        assert_eq!(endpoint_of("[123:456:ERROR] something"), None);
        assert_eq!(endpoint_of("DevTools listening on http://x"), None);
    }

    #[test]
    fn explicit_missing_binary_is_none() {
        assert_eq!(find_chrome(Some(Path::new("/nonexistent/chrome"))), None);
    }
}
