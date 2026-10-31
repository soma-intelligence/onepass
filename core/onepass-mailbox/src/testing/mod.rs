//! Test support (feature `testing`): an in-memory mailbox that follows the
//! SQL of `mailbox/supabase/migrations/`, and the conformance suite that
//! holds it and the real server to the same behaviour (spec 4.14, 11).

pub mod conformance;
mod fake;

pub use conformance::{ConformanceTarget, QUOTA_CASE_MAX_RECORDS, run_conformance};
pub use fake::{FAKE_BASE_URL, FakeMailbox, FakeMailboxClient, FaultHandle};
