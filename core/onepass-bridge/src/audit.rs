//! Local journal of the requests that disclosed a secret or wrote to the
//! vault (spec 7.5). An event never holds a value: operation, item,
//! origin, context and time only.

use std::sync::{Arc, Mutex};

use crate::api::Ctx;

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Wire name of the operation.
    pub op: &'static str,
    /// Item id, hyphenated.
    pub item_id: String,
    /// Origin of the request, when it had one.
    pub origin: Option<String>,
    pub ctx: Ctx,
    /// Unix seconds.
    pub at: u64,
}

/// Where the service writes its journal.
pub trait AuditSink: Send {
    fn record(&mut self, event: AuditEvent);
}

/// In-memory journal. Clones share the same entries, so a test can keep a
/// handle while the service owns another.
#[derive(Debug, Clone, Default)]
pub struct MemoryAudit {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MemoryAudit {
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of the entries so far.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl AuditSink for MemoryAudit {
    fn record(&mut self, event: AuditEvent) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_entries() {
        let handle = MemoryAudit::new();
        let mut sink: Box<dyn AuditSink> = Box::new(handle.clone());
        sink.record(AuditEvent {
            op: "fill_login",
            item_id: "i".into(),
            origin: Some("https://atlas-cloud.test".into()),
            ctx: Ctx::Menu,
            at: 7,
        });
        assert_eq!(handle.events().len(), 1);
        assert_eq!(handle.events()[0].op, "fill_login");
    }
}
