//! A whole fill: every field in turn, then maybe the submit, within 30 s.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::{CdpError, CdpPage};

pub(crate) const FILL_TIMEOUT: Duration = Duration::from_secs(30);

/// One field and the value to type into it. The value is zeroed on drop.
pub struct FillStep {
    pub backend_node_id: i64,
    pub value: Zeroizing<String>,
}

impl FillStep {
    pub fn new(backend_node_id: i64, value: Zeroizing<String>) -> Self {
        FillStep {
            backend_node_id,
            value,
        }
    }
}

impl std::fmt::Debug for FillStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FillStep")
            .field("backend_node_id", &self.backend_node_id)
            .finish_non_exhaustive()
    }
}

impl CdpPage {
    /// Types each step's value with [`CdpPage::type_into`] (origin read
    /// again before each), then clicks `submit` when given. Stops at the
    /// first error and types nothing more; the 30 s limit covers it all.
    /// Every value is zeroed when this returns.
    pub fn fill(&mut self, steps: Vec<FillStep>, submit: Option<i64>) -> Result<(), CdpError> {
        let end = Instant::now() + self.whole_fill();
        let outer = self.socket().deadline;
        self.socket().deadline = Some(outer.map_or(end, |o| o.min(end)));
        let r = (|| {
            for s in &steps {
                self.type_into(s.backend_node_id, &s.value)?;
            }
            if let Some(b) = submit {
                self.click(b)?;
            }
            Ok(())
        })();
        self.socket().deadline = outer;
        drop(steps);
        r
    }
}
