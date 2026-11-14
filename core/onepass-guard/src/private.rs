//! Files only this user may read: the audit log, its head, the signed
//! configuration files and their lock files.
//!
//! - Unix: created with mode 0600 (and 0600 enforced on an existing file),
//!   lock files opened with `O_NOFOLLOW`, directories synced after a rename.
//! - Windows: no mode bits. The data directory lives under the user's
//!   profile (`%LOCALAPPDATA%`), whose inherited ACL admits only the user,
//!   SYSTEM and administrators; a file created there gets that ACL. Lock
//!   files are opened with `FILE_FLAG_OPEN_REPARSE_POINT`, the counterpart
//!   of `O_NOFOLLOW`: a planted symlink or junction is opened itself, never
//!   followed. A directory cannot be synced (NTFS journals the rename).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Sets the creation mode 0600 (Unix; nothing to set on Windows).
pub fn private(opts: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
    }
    #[cfg(not(unix))]
    {
        opts
    }
}

/// Never follows a symlink at the last component.
pub fn no_follow(opts: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// `FILE_FLAG_OPEN_REPARSE_POINT`.
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(OPEN_REPARSE_POINT)
    }
}

/// Enforces 0600 on an open file (Unix; the inherited ACL on Windows).
pub fn set_private(f: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = f;
        Ok(())
    }
}

/// Makes a rename in `dir` durable (Unix; a no-op on Windows).
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Reads exactly `buf.len()` bytes at `pos`.
#[cfg(unix)]
pub fn read_exact_at(f: &File, buf: &mut [u8], pos: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, pos)
}

/// Reads exactly `buf.len()` bytes at `pos`. `seek_read` moves the cursor
/// on Windows: callers only use positioned reads and appends.
#[cfg(windows)]
pub fn read_exact_at(f: &File, mut buf: &mut [u8], mut pos: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match f.seek_read(buf, pos) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                pos += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn positioned_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let mut f = private(OpenOptions::new().create(true).write(true).read(true))
            .open(&path)
            .unwrap();
        f.write_all(b"0123456789").unwrap();
        set_private(&f).unwrap();
        let mut buf = [0u8; 4];
        read_exact_at(&f, &mut buf, 3).unwrap();
        assert_eq!(&buf, b"3456");
        assert!(read_exact_at(&f, &mut buf, 8).is_err());
        sync_dir(dir.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let f = private(OpenOptions::new().create(true).write(true))
            .open(&path)
            .unwrap();
        drop(f);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
