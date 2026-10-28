//! The development host's side of the connection loop of
//! `onepass_bridge::host`: pairings in `pairings.json`, approval `auto`
//! (the code goes to the journal) or `file` (`pending-pairing.json`, then
//! `pairing-approved`), and the journal file.

use std::path::{Path, PathBuf};

use onepass_bridge::host::{Approval, Approver, Journal, PairingStore};
use onepass_bridge::pairing::PairingRecord;
use serde_json::json;
use zeroize::Zeroizing;

use crate::config::Approval as Mode;
use crate::log::Log;
use crate::pairings::{Pairings, write_atomic};

pub const PENDING_FILE: &str = "pending-pairing.json";
pub const APPROVED_FILE: &str = "pairing-approved";

impl Journal for Log {
    fn line(&self, msg: &str) {
        Log::line(self, msg);
    }
}

impl PairingStore for Pairings {
    fn key(&self, id: &[u8; 16]) -> Option<Zeroizing<[u8; 32]>> {
        Pairings::key(self, id)
    }
    fn add(&mut self, record: &PairingRecord, extension_id: &str) -> Result<(), String> {
        Pairings::add(self, record, extension_id).map_err(|e| e.to_string())
    }
    fn touch(&mut self, id: &[u8; 16], now: u64) -> Result<(), String> {
        Pairings::touch(self, id, now).map_err(|e| e.to_string())
    }
}

/// Approval of the development host, by configuration.
pub struct DevApprover {
    mode: Mode,
    data_dir: PathBuf,
    log: Log,
    sas: String,
}

impl DevApprover {
    pub fn new(mode: Mode, data_dir: &Path, log: Log) -> DevApprover {
        DevApprover {
            mode,
            data_dir: data_dir.to_path_buf(),
            log,
            sas: String::new(),
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.data_dir.join(name)
    }

    fn clear(&self) {
        let _ = std::fs::remove_file(self.file(PENDING_FILE));
        let _ = std::fs::remove_file(self.file(APPROVED_FILE));
    }
}

impl Approver for DevApprover {
    fn begin(&mut self, sas: &str, ext_name: &str, browser: &str) -> Result<(), String> {
        // The code is derived by the host: not extension input.
        self.log.line(&format!("pairing code: {sas}"));
        self.sas = sas.to_owned();
        if self.mode == Mode::Auto {
            return Ok(());
        }
        // A stale approval must not approve this pairing.
        self.clear();
        let pending = json!({"sas": sas, "ext_name": ext_name, "browser": browser});
        write_atomic(&self.file(PENDING_FILE), pending.to_string().as_bytes())
            .map_err(|e| format!("cannot write {PENDING_FILE}: {}", e.kind()))
    }

    /// `auto`: approved. `file`: approved when `pairing-approved` holds the
    /// same code, refused when it holds another one.
    fn poll(&mut self) -> Approval {
        if self.mode == Mode::Auto {
            return Approval::Approved;
        }
        match std::fs::read_to_string(self.file(APPROVED_FILE)) {
            Ok(code) if same_code(&code, &self.sas) => Approval::Approved,
            Ok(_) => {
                self.log.line("pairing refused: wrong code");
                Approval::Refused
            }
            Err(_) => Approval::Pending,
        }
    }

    fn end(&mut self) {
        if self.mode == Mode::File {
            self.clear();
        }
    }
}

/// Two codes are the same once spaces are removed (`123 456`, `123456`).
fn same_code(a: &str, b: &str) -> bool {
    let digits = |s: &str| -> String { s.chars().filter(|c| !c.is_whitespace()).collect() };
    let (a, b) = (digits(a), digits(b));
    !a.is_empty() && a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_compare_without_spaces() {
        assert!(same_code("123 456\n", "123 456"));
        assert!(same_code("123456", "123 456"));
        assert!(!same_code("123 457", "123 456"));
        assert!(!same_code("", ""));
    }

    #[test]
    fn file_mode_waits_then_follows_the_approved_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = DevApprover::new(Mode::File, dir.path(), Log::stderr());
        a.begin("123 456", "OnePass", "Chromium").unwrap();
        assert!(dir.path().join(PENDING_FILE).exists());
        assert_eq!(a.poll(), Approval::Pending);
        std::fs::write(dir.path().join(APPROVED_FILE), "123456").unwrap();
        assert_eq!(a.poll(), Approval::Approved);
        a.end();
        assert!(!dir.path().join(PENDING_FILE).exists());
        assert!(!dir.path().join(APPROVED_FILE).exists());

        a.begin("123 456", "OnePass", "Chromium").unwrap();
        std::fs::write(dir.path().join(APPROVED_FILE), "999 999").unwrap();
        assert_eq!(a.poll(), Approval::Refused);
    }

    #[test]
    fn begin_clears_a_stale_approval() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(APPROVED_FILE), "123 456").unwrap();
        let mut a = DevApprover::new(Mode::File, dir.path(), Log::stderr());
        a.begin("123 456", "OnePass", "Chromium").unwrap();
        assert_eq!(a.poll(), Approval::Pending);
    }
}
