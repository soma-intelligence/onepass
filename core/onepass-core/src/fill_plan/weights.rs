//! Weights of the candidate score (spec R4).

pub const EXACT: i64 = 100;
pub const DOMAIN: i64 = 60;
pub const LAST_ON_SITE: i64 = 80;
pub const SAME_SHAPE: i64 = 20;
pub const TYPED_USERNAME: i64 = 1000;
pub const FAVORITE: i64 = 5;
pub const RECENCY_MAX: i64 = 5;
pub const FREQUENCY_MAX: i64 = 5;
/// Lead the best candidate needs over the second one to be trusted.
pub const MARGIN: i64 = 40;
/// Minimum role confidence for a field to be filled without asking.
pub const ROLE_MIN: f32 = 0.6;
