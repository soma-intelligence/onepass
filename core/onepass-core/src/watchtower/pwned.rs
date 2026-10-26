//! Password breach lookups by k-anonymity (spec 3.3).

/// Source of HIBP `range` responses.
pub trait RangeSource {
    /// Response body for a prefix of 5 upper-case hex characters.
    fn range(&mut self, prefix: &str) -> crate::Result<Vec<u8>>;
}
