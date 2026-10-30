//! Smart one-click fill plan: value-free page context, intent rules, ranking
//! and one composed plan for the page.

pub mod compose;
pub mod context;
pub mod intent;
pub mod score;
pub mod weights;

pub use compose::{
    Action, FillPlan, GroupItem, GroupKind, PlanGroup, Pool, ReasonCode, page_intent, plan,
};
