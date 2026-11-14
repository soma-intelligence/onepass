//! The pinned organisation on disk: `pin.bin` in the app's state folder for
//! that org, `OrgPin::encode` (no serde). Written whole to a temporary file
//! in the same folder, then renamed over the old one: a crash or a refused
//! update leaves the previous pin byte for byte. The folder is private
//! (0700 on Unix).

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use onepass_core::org::OrgPin;

use crate::error::OnePassError;

const PIN_FILE: &str = "pin.bin";

static PIN_LOCK: Mutex<()> = Mutex::new(());

/// Held around every read-compare-write of a pin in this process, so two
/// clients on the same folder never write an older pin over a newer one.
/// (Another process is not covered: one app process owns its state folder.)
pub(crate) fn pin_lock() -> MutexGuard<'static, ()> {
    PIN_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The pin in `dir`, `None` when there is none yet. A pin that does not
/// decode is refused (`InvalidInput`), never replaced silently.
pub(crate) fn load_pin(dir: &Path) -> Result<Option<OrgPin>, OnePassError> {
    match fs::read(dir.join(PIN_FILE)) {
        Ok(bytes) => Ok(Some(OrgPin::decode(&bytes)?)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(OnePassError::Store),
    }
}

/// Replace the pin in `dir` (created 0700 if missing) atomically.
pub(crate) fn save_pin(dir: &Path, pin: &OrgPin) -> Result<(), OnePassError> {
    write_atomic(dir, &pin.encode()).map_err(|_| OnePassError::Store)
}

fn write_atomic(dir: &Path, bytes: &[u8]) -> std::io::Result<()> {
    create_private_dir(dir)?;
    // A name of its own per write: two writers never share a temporary file.
    let suffix =
        onepass_core::crypto::random_array::<8>().map_err(|_| std::io::Error::other("random"))?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!("{PIN_FILE}.{}.{suffix}.tmp", std::process::id()));
    let written = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(PIN_FILE))
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // The rename itself reaches the disk with the folder.
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    // An existing folder (made by the app) is narrowed too.
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)
}
