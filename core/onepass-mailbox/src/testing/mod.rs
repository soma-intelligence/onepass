//! Test support (feature `testing`): an in-memory mailbox that follows the
//! SQL of `mailbox/supabase/migrations/`, and the conformance suite that
//! holds it and the real server to the same behaviour (spec 4.14, 11).

pub mod conformance;
mod fake;

pub use conformance::{ConformanceTarget, QUOTA_CASE_MAX_RECORDS, run_conformance};
pub use fake::{FAKE_BASE_URL, FakeMailbox, FakeMailboxClient, FaultHandle};

use crate::MailboxError;
use crate::credential::Credential;

impl Credential {
    /// A fresh pair from the system's random source, for tests only (feature
    /// `testing`, refused in release builds). Shipped credentials come from a
    /// seed the core draws from its hedged source (`Credential::from_seed`).
    pub fn generate() -> Result<Credential, MailboxError> {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(&mut seed[..]).map_err(|_| MailboxError::Rng)?;
        Credential::from_seed(&seed[..])
    }
}
