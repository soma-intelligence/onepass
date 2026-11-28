//! The native open and save dialogs, run by the backend: the path the user
//! picks never crosses the IPC, and the web view cannot read or write a file
//! on its own (no fs or dialog plugin, spec 2026-10-30 section 3.2).
//!
//! Debug builds only: the end-to-end test answers a dialog by writing the
//! path to return into the file named by ONEPASS_E2E_DIALOG (an empty file
//! means "Cancel"). A release build always shows the dialog.

use std::path::PathBuf;

use tauri::WebviewWindow;

/// A file type offered by a dialog: its name and its extensions.
pub type Filter<'a> = (&'a str, &'a [&'a str]);

fn e2e_answer() -> Option<Option<PathBuf>> {
    #[cfg(debug_assertions)]
    if let Some(file) = std::env::var_os("ONEPASS_E2E_DIALOG") {
        let answer = std::fs::read_to_string(file).unwrap_or_default();
        let answer = answer.trim();
        return Some((!answer.is_empty()).then(|| PathBuf::from(answer)));
    }
    None
}

/// Runs a dialog off the event loop's thread, modal to the app's window.
async fn run<F>(f: F) -> Option<PathBuf>
where
    F: FnOnce() -> Option<PathBuf> + Send + 'static,
{
    if let Some(answer) = e2e_answer() {
        return answer;
    }
    tauri::async_runtime::spawn_blocking(f).await.ok().flatten()
}

/// Asks for a file to open. `None` when the user cancels.
pub async fn pick_file(
    window: &WebviewWindow,
    title: &str,
    filters: &[Filter<'_>],
) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new().set_title(title).set_parent(window);
    for (name, ext) in filters {
        dialog = dialog.add_filter(*name, ext);
    }
    run(move || dialog.pick_file()).await
}

/// Asks where to save a file named `name` by default. `None` on cancel.
pub async fn save_file(
    window: &WebviewWindow,
    title: &str,
    name: &str,
    filters: &[Filter<'_>],
) -> Option<PathBuf> {
    let mut dialog = rfd::FileDialog::new()
        .set_title(title)
        .set_file_name(name)
        .set_parent(window);
    for (n, ext) in filters {
        dialog = dialog.add_filter(*n, ext);
    }
    run(move || dialog.save_file()).await
}

/// Reads a picked file, refusing one larger than `max` bytes.
pub fn read_limited(path: &std::path::Path, max: u64) -> Result<Vec<u8>, ReadError> {
    let meta = std::fs::metadata(path).map_err(|_| ReadError::Unreadable)?;
    if meta.len() > max {
        return Err(ReadError::TooLarge);
    }
    let bytes = std::fs::read(path).map_err(|_| ReadError::Unreadable)?;
    if bytes.len() as u64 > max {
        return Err(ReadError::TooLarge);
    }
    Ok(bytes)
}

pub enum ReadError {
    TooLarge,
    Unreadable,
}

impl From<ReadError> for crate::view::UiError {
    fn from(e: ReadError) -> Self {
        let (code, detail) = match e {
            ReadError::TooLarge => ("TooLarge", "this file is too large"),
            ReadError::Unreadable => ("Unreadable", "this file could not be read"),
        };
        crate::view::UiError {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

/// The file name of a path, for display and as an attachment name.
pub fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The media type of a file by its extension (the attachment's `mime`).
pub fn mime_for(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("bmp") => "image/bmp",
        Some("svg") => "image/svg+xml",
        Some("txt" | "log") => "text/plain",
        Some("csv") => "text/csv",
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("zip") => "application/zip",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("pem" | "key") => "application/x-pem-file",
        _ => "application/octet-stream",
    }
}
