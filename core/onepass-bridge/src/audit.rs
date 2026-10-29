//! Local journal of the requests that disclosed a secret or wrote to the
//! vault, and of the fill plans (spec 7.5). An event never holds a value:
//! operation, item, origin, context and time only, and for a plan its
//! intent, action and confidence (never a field ref nor a role).

use std::sync::{Arc, Mutex};

use onepass_core::fill_plan::intent::Intent;
use onepass_core::fill_plan::score::Confidence;
use onepass_core::fill_plan::{Action, FillPlan};
use serde::Serialize;

use crate::api::Ctx;

/// What the journal keeps of a fill plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlanAudit {
    pub intent: Intent,
    pub action: Action,
    pub confidence: Confidence,
}

impl From<&FillPlan> for PlanAudit {
    fn from(p: &FillPlan) -> PlanAudit {
        PlanAudit {
            intent: p.intent,
            action: p.action,
            confidence: p.confidence,
        }
    }
}

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Wire name of the operation.
    pub op: &'static str,
    /// Item id, hyphenated, when the operation names one.
    pub item_id: Option<String>,
    /// Origin of the request, when it had one; the host alone for
    /// `plan_fill` and `note_fill`, the site for `forget_site`.
    pub origin: Option<String>,
    pub ctx: Ctx,
    /// Unix seconds.
    pub at: u64,
    /// `plan_fill` only.
    pub plan: Option<PlanAudit>,
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
            item_id: Some("i".into()),
            origin: Some("https://atlas-cloud.test".into()),
            ctx: Ctx::Menu,
            at: 7,
            plan: None,
        });
        assert_eq!(handle.events().len(), 1);
        assert_eq!(handle.events()[0].op, "fill_login");
    }
}
