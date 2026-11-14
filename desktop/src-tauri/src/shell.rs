//! Hand-offs to Windows: a website opens in the default browser, an
//! attachment in the app registered for its type. Only these two, each
//! checked here; the web view never names a program or a path.

/// A website of an item, as the browser should receive it: http or https
/// only, a host, no credentials. A bare host ("github.com") gets https.
pub fn web_url(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() || text.len() > 2048 || text.chars().any(|c| c.is_control() || c == '\\') {
        return Err("not a website address".into());
    }
    let lower = text.to_ascii_lowercase();
    let candidate = if lower.starts_with("http://") || lower.starts_with("https://") {
        text.to_owned()
    } else if !text.contains(':') || text.split('/').next().is_some_and(is_host_port) {
        format!("https://{text}")
    } else {
        return Err("only http and https websites open".into());
    };
    let url = url::Url::parse(&candidate).map_err(|_| "not a website address")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("only http and https websites open".into());
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("not a website address".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("an address with credentials does not open".into());
    }
    Ok(url.into())
}

/// "example.com:8080": a host and a port, not a scheme.
fn is_host_port(s: &str) -> bool {
    s.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && host.contains('.')
            && !port.is_empty()
            && port.chars().all(|c| c.is_ascii_digit())
    })
}

/// Opens a checked web URL in the default browser.
pub fn open_web(url: &str) -> Result<(), String> {
    let url = web_url(url)?;
    if e2e_log(&url) {
        return Ok(());
    }
    shell_open(&url)
}

/// Debug builds only: with ONEPASS_E2E_SHELL_LOG set, the end-to-end test
/// records what would open instead of starting a browser or a viewer.
pub fn e2e_log(target: &str) -> bool {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("ONEPASS_E2E_SHELL_LOG") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{target}");
        }
        return true;
    }
    let _ = target;
    false
}

#[cfg(windows)]
fn shell_open(target: &str) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let verb = wide("open");
    let target = wide(target);
    // SAFETY: NUL-terminated UTF-16 strings that outlive the call; no
    // parent window, parameters or directory.
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute returns a value above 32 on success.
    if r as isize > 32 {
        Ok(())
    } else {
        Err(format!("Windows could not open it ({})", r as isize))
    }
}

#[cfg(not(windows))]
fn shell_open(_target: &str) -> Result<(), String> {
    Err("not supported on this system".into())
}

/// Kinds of file an attachment may open as: documents and pictures. A
/// program, a script or a shortcut is never handed to Windows to "open"
/// (it would run); the user can still export it.
pub fn opens_safely(name: &str) -> bool {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    matches!(
        ext.as_deref(),
        Some(
            "pdf"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "bmp"
                | "heic"
                | "tif"
                | "tiff"
                | "txt"
                | "log"
                | "md"
                | "csv"
                | "json"
                | "rtf"
                | "docx"
                | "xlsx"
                | "pptx"
                | "odt"
                | "ods"
                | "odp"
        )
    )
}

/// A file name safe to create in a folder: no path, no reserved character.
pub fn safe_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_owned();
    if cleaned.is_empty() {
        "file".into()
    } else {
        cleaned
    }
}

/// Opens a file with the app Windows associates with it, marked as coming
/// from the Internet (Mark of the Web) so Office and others open it in
/// protected view.
pub fn open_file(path: &std::path::Path) -> Result<(), String> {
    let mut zone = path.as_os_str().to_owned();
    zone.push(":Zone.Identifier");
    let _ = std::fs::write(zone, "[ZoneTransfer]\r\nZoneId=3\r\n");
    let target = path.to_string_lossy();
    if e2e_log(&target) {
        return Ok(());
    }
    shell_open(&target)
}

#[cfg(test)]
mod tests {
    use super::web_url;

    #[test]
    fn only_http_and_https_open() {
        assert_eq!(
            web_url("https://github.com").unwrap(),
            "https://github.com/"
        );
        assert_eq!(
            web_url("http://example.com/a?b=c").unwrap(),
            "http://example.com/a?b=c"
        );
        assert_eq!(
            web_url("github.com/login").unwrap(),
            "https://github.com/login"
        );
        assert_eq!(
            web_url("example.com:8443").unwrap(),
            "https://example.com:8443/"
        );
        assert_eq!(
            web_url("  HTTPS://Example.com ").unwrap(),
            "https://example.com/"
        );
        for bad in [
            "javascript:alert(1)",
            "file:///C:/Windows/system32/calc.exe",
            "ms-settings:privacy",
            "mailto:a@b.c",
            "https://user:pw@example.com",
            "https://",
            "",
            "https://exa\u{0}mple.com",
            "\\\\server\\share",
            "C:\\Windows\\notepad.exe",
        ] {
            assert!(web_url(bad).is_err(), "{bad} must not open");
        }
    }
}
